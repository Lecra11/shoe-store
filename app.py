from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import json

app = Flask(__name__)
import os

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'store.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Required for sessions and flash messages
db = SQLAlchemy(app)

# Forgot password route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash('Please enter your email address', 'error')
            return render_template('reset_password.html', token=None)
        
        user = User.query.filter_by(email=email).first()
        # Always show the same message for security
        flash('If your email is registered, you will receive a password reset link shortly.', 'success')
        
        if user:
            # Generate reset token and save to user
            token = user.generate_reset_token()
            db.session.commit()
            # In production, send this link via email
            reset_url = url_for('reset_password', token=token, _external=True)
            # For demonstration, show the link in the flash message
            flash(f'Password reset link (for demo): {reset_url}', 'info')
        return render_template('reset_password.html', token=None)
    return render_template('reset_password.html', token=None)

# Reset password route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if not token:
        flash('Invalid reset link', 'error')
        return redirect(url_for('auth'))
    
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.verify_reset_token(token):
        flash('The password reset link is invalid or has expired', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not password or not confirm_password:
            flash('Please fill in all fields', 'error')
            return render_template('reset_password.html', token=token)
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('reset_password.html', token=token)
        
        user.set_password(password)
        user.clear_reset_token()
        db.session.commit()
        flash('Your password has been updated! You can now log in with your new password.', 'success')
        return redirect(url_for('auth'))
    
    return render_template('reset_password.html', token=token)

# Models
import secrets
from datetime import datetime, timedelta

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)
    orders = db.relationship('Order', backref='user', lazy=True)

    # Password reset fields
    reset_token = db.Column(db.String(100))
    reset_token_expiry = db.Column(db.DateTime)

    # Personal Information
    gender = db.Column(db.String(20))  # male, female, prefer not to say

    # Shipping Information
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address_line1 = db.Column(db.String(200))
    address_line2 = db.Column(db.String(200))
    city = db.Column(db.String(100))
    province = db.Column(db.String(100))
    postal_code = db.Column(db.String(20))

    # Additional user information
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    shipping_info_updated_at = db.Column(db.DateTime)

    def update_shipping_info(self, data):
        self.full_name = data.get('full_name')
        self.phone = data.get('phone')
        self.address_line1 = data.get('address_line1')
        self.address_line2 = data.get('address_line2')
        self.city = data.get('city')
        self.province = data.get('province')
        self.postal_code = data.get('postal_code')
        self.shipping_info_updated_at = datetime.utcnow()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Password reset methods
    def generate_reset_token(self):
        token = secrets.token_urlsafe(32)
        self.reset_token = token
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        return token

    def verify_reset_token(self, token):
        if self.reset_token != token:
            return False
        if not self.reset_token_expiry or self.reset_token_expiry < datetime.utcnow():
            return False
        return True

    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expiry = None

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')  # pending, paid, shipped, delivered, cancelled, refund, complete
    payment_method = db.Column(db.String(50))  # gcash, maya, cod
    payment_status = db.Column(db.String(50), default='pending')  # pending, completed
    shipping_fee = db.Column(db.Float, default=100.00)
    total_amount = db.Column(db.Float, nullable=False)
    expected_delivery_date = db.Column(db.DateTime)  # New field for expected delivery date
    cancel_refund_reason = db.Column(db.Text)  # New field for cancellation/refund reason
    
    # Shipping Information (copied from user but can be different)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address_line1 = db.Column(db.String(200), nullable=False)
    address_line2 = db.Column(db.String(200))
    city = db.Column(db.String(100), nullable=False)
    province = db.Column(db.String(100), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    
    # Payment Information
    payment_reference = db.Column(db.String(100))  # For GCash/Maya reference numbers
    
    # Relationships
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    variation_id = db.Column(db.Integer, db.ForeignKey('product_variation.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)  # Price at time of purchase
    variation = db.relationship('ProductVariation', backref='order_items', lazy=True)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    variation_id = db.Column(db.Integer, db.ForeignKey('product_variation.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.template_filter('unique')
def unique_filter(items, attribute=None):
    if attribute:
        seen = set()
        result = []
        for item in items:
            value = getattr(item, attribute)
            if value not in seen:
                seen.add(value)
                result.append(item)
        return result
    return list(set(items))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    base_price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50))
    brand = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    variations = db.relationship('ProductVariation', backref='product', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'base_price': self.base_price,
            'category': self.category,
            'brand': self.brand,
            'created_at': self.created_at.isoformat(),
            'variations': [variation.to_dict() for variation in self.variations]
        }

class ProductVariation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    size = db.Column(db.String(10), nullable=False)
    color = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(200))
    cart_items = db.relationship('CartItem', backref='variation', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'product_id': self.product_id,
            'size': self.size,
            'color': self.color,
            'price': self.price,
            'stock': self.stock,
            'image_url': self.image_url
        }

# Authentication routes
@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'GET':
        return render_template('auth.html')
    
    # Determine if this is a signup or login based on a hidden form field 'action'
    action = request.form.get('action', 'login')
    
    if action == 'signup':
        # Handle signup
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        # Optional personal info fields (not required)
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        address_line1 = request.form.get('address_line1', '').strip()
        address_line2 = request.form.get('address_line2', '').strip()
        city = request.form.get('city', '').strip()
        province = request.form.get('province', '').strip()
        postal_code = request.form.get('postal_code', '').strip()
        gender = request.form.get('gender', '').strip()
        
        # Validate required fields
        if not username or not email or not password:
            flash('Please fill in all required fields', 'error')
            return render_template('auth.html')
        
        # Validate email format
        if '@' not in email or '.' not in email:
            flash('Please enter a valid email address', 'error')
            return render_template('auth.html')
        
        # Validate password length
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('auth.html')
        
        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('auth.html')
        
        # Check if email exists    
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('auth.html')
        
        # Create new user
        try:
            user = User(
                username=username,
                email=email,
                full_name=full_name if full_name else None,
                phone=phone if phone else None,
                address_line1=address_line1 if address_line1 else None,
                address_line2=address_line2 if address_line2 else None,
                city=city if city else None,
                province=province if province else None,
                postal_code=postal_code if postal_code else None,
                gender=gender if gender else None
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('auth.html')
    else:
        # Handle login
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please fill in all fields', 'error')
            return render_template('auth.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            
            # Update last login time
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Logged in successfully!', 'success')
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('index'))
        
        flash('Invalid username or password', 'error')
        return render_template('auth.html')

# Removed signup route

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash('Please login to access settings', 'error')
        return redirect(url_for('auth'))
    
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('auth'))
    
    # Disable editing personal info if already set
    personal_info_set = all([
        user.full_name,
        user.phone,
        user.address_line1,
        user.city,
        user.province,
        user.postal_code
    ])
    
    if request.method == 'POST':
        if personal_info_set:
            # Do not allow changes to personal info once set
            flash('Personal information cannot be changed once saved.', 'error')
            return render_template('settings.html', user=user, personal_info_set=personal_info_set)
        
        # Update personal info only once
        full_name = request.form.get('full_name', '').strip()
        gender = request.form.get('gender', '').strip()
        phone = request.form.get('phone', '').strip()
        address_line1 = request.form.get('address_line1', '').strip()
        address_line2 = request.form.get('address_line2', '').strip()
        city = request.form.get('city', '').strip()
        province = request.form.get('province', '').strip()
        postal_code = request.form.get('postal_code', '').strip()
        
        if not full_name or not phone or not address_line1 or not city or not province or not postal_code:
            flash('Please fill in all required personal information fields', 'error')
            return render_template('settings.html', user=user, personal_info_set=personal_info_set)
        
        user.full_name = full_name
        user.gender = gender
        user.phone = phone
        user.address_line1 = address_line1
        user.address_line2 = address_line2
        user.city = city
        user.province = province
        user.postal_code = postal_code
        user.shipping_info_updated_at = datetime.utcnow()
        
        db.session.commit()
        # Removed flash message "Logged in successfully!"
        return redirect(url_for('settings'))
    
    return render_template('settings.html', user=user, personal_info_set=personal_info_set)

@app.route('/deactivate_account', methods=['POST'])
def deactivate_account():
    if 'user_id' not in session:
        flash('Please login to deactivate account', 'error')
        return redirect(url_for('auth'))
    
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('auth'))
    
    password = request.form.get('password', '').strip()
    if not password or not user.check_password(password):
        flash('Incorrect password', 'error')
        return redirect(url_for('settings'))
    
    # Check for pending or undelivered orders
    pending_orders = Order.query.filter(
        Order.user_id == user.id,
        Order.status.in_(['pending', 'paid', 'shipped'])
    ).count()
    
    if pending_orders > 0:
        flash('Cannot deactivate account with pending or undelivered orders', 'error')
        return redirect(url_for('settings'))
    
    # Deactivate account - here we delete the user and related data
    try:
        # Delete user's cart items
        CartItem.query.filter_by(user_id=user.id).delete()
        # Delete user's orders and order items
        orders = Order.query.filter_by(user_id=user.id).all()
        for order in orders:
            try:
                OrderItem.query.filter_by(order_id=order.id).delete()
            except Exception as e:
                print(f"Error deleting order items: {str(e)}")
            db.session.delete(order)
        # Delete user
        db.session.delete(user)
        db.session.commit()
        session.clear()
        flash('Account deactivated successfully', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deactivating account. Please try again.', 'error')
        return redirect(url_for('settings'))

@app.route('/change_account')
def change_account():
    # Placeholder for change account page
    if 'user_id' not in session:
        flash('Please login to change account', 'error')
        return redirect(url_for('auth'))
    return "Change account page - to be implemented"

# Cart routes
@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash('Please login to view your cart', 'error')
        return redirect(url_for('auth'))
    
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    subtotal = sum(item.variation.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, subtotal=subtotal)

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        flash('Please login to proceed to checkout', 'error')
        return redirect(url_for('auth'))
    
    if request.method == 'GET':
        cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
        if not cart_items:
            return redirect(url_for('cart'))
        
        user = User.query.get(session['user_id'])
        subtotal = sum(item.variation.price * item.quantity for item in cart_items)
        return render_template('checkout.html', cart_items=cart_items, user=user, subtotal=subtotal)
    
    # Handle POST request
    data = request.get_json()
    shipping = data.get('shipping')
    payment_method = data.get('payment_method')
    
    # Get cart items
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    if not cart_items:
        return jsonify({'success': False, 'message': 'Cart is empty'})
    
    # Calculate total
    subtotal = sum(item.variation.price * item.quantity for item in cart_items)
    total = subtotal + 100  # Adding shipping fee
    
    try:
        # Create order
        order = Order(
            user_id=session['user_id'],
            payment_method=payment_method,
            total_amount=total,
            full_name=shipping['full_name'],
            phone=shipping['phone'],
            address_line1=shipping['address_line1'],
            address_line2=shipping.get('address_line2', ''),
            city=shipping['city'],
            province=shipping['province'],
            postal_code=shipping['postal_code']
        )
        db.session.add(order)
        
        # Create order items
        for cart_item in cart_items:
            order_item = OrderItem(
                order=order,
                variation_id=cart_item.variation_id,
                quantity=cart_item.quantity,
                price=cart_item.variation.price
            )
            db.session.add(order_item)
            
            # Update stock
            variation = cart_item.variation
            variation.stock -= cart_item.quantity
            db.session.add(variation)
        
        # Clear cart
        for item in cart_items:
            db.session.delete(item)
        
        # Save all changes
        db.session.commit()
        
        return jsonify({
            'success': True,
            'order_id': order.id
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'})

@app.route('/payment/<int:order_id>')
def payment(order_id):
    if 'user_id' not in session:
        flash('Please login to view payment details', 'error')
        return redirect(url_for('auth'))
    
    order = Order.query.get_or_404(order_id)
    if order.user_id != session['user_id']:
        abort(403)
    
    return render_template('payment.html', order=order)

@app.route('/payment/<int:order_id>/confirm', methods=['POST'])
def confirm_payment(order_id):
    if 'user_id' not in session:
        return redirect(url_for('auth'))
    
    order = Order.query.get_or_404(order_id)
    if order.user_id != session['user_id']:
        abort(403)
    
    data = request.get_json()
    reference = data.get('reference')
    
    if not reference:
        return jsonify({
            'success': False,
            'message': 'Reference number is required'
        })
    
    order.payment_reference = reference
    order.payment_status = 'completed'
    order.status = 'paid'
    # Set expected delivery date to 7 days from now as example
    order.expected_delivery_date = datetime.utcnow() + timedelta(days=7)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'order_id': order.id
    })

@app.route('/order/confirmation/<int:order_id>')
def order_confirmation(order_id):
    if 'user_id' not in session:
        flash('Please login to view order confirmation', 'error')
        return redirect(url_for('auth'))
    
    order = Order.query.get_or_404(order_id)
    if order.user_id != session['user_id']:
        abort(403)
    
    return render_template('order_confirmation.html', order=order)

# New route: Customer view orders
@app.route('/orders')
def customer_orders():
    if 'user_id' not in session:
        flash('Please login to view your orders', 'error')
        return redirect(url_for('auth'))
    
    user_id = session['user_id']
    orders = Order.query.filter_by(user_id=user_id).order_by(Order.order_date.desc()).all()
    return render_template('orders.html', orders=orders)

# New route: Update order status (cancel/refund/received) by customer or admin
@app.route('/order/<int:order_id>/update_status', methods=['POST'])
def update_order_status(order_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401
    
    order = Order.query.get_or_404(order_id)
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    # Only allow owner or admin to update
    if order.user_id != user_id and not is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    new_status = data.get('status')
    reason = data.get('reason', None)
    
    valid_statuses = ['cancelled', 'refund', 'complete', 'received']
    if new_status not in valid_statuses:
        return jsonify({'success': False, 'message': 'Invalid status'}), 400
    
    # Business logic: customers can only set 'cancelled', 'refund', 'received'
    # Admin can set 'complete' as well
    if not is_admin and new_status == 'complete':
        return jsonify({'success': False, 'message': 'Unauthorized status update'}), 403
    
    # If order is being cancelled or refunded, restore stock
    if new_status in ['cancelled', 'refund']:
        for item in order.items:
            variation = item.variation
            variation.stock += item.quantity
            db.session.add(variation)
    
    # Update status and reason
    if new_status == 'received':
        order.status = 'complete'
    else:
        order.status = new_status
    
    if new_status in ['cancelled', 'refund'] and reason:
        order.cancel_refund_reason = reason
    
    db.session.commit()
    
    return jsonify({'success': True, 'new_status': order.status})

@app.route('/cart/add/<int:variation_id>', methods=['POST'])
def add_to_cart(variation_id):
    if 'user_id' not in session:
        flash('Please login to add items to cart', 'error')
        return jsonify({'error': 'Authentication required'}), 401
    
    quantity = int(request.form.get('quantity', 1))
    cart_item = CartItem(user_id=session['user_id'], variation_id=variation_id, quantity=quantity)
    db.session.add(cart_item)
    db.session.commit()
    
    return jsonify({'message': 'Added to cart successfully'})

@app.route('/cart/remove/<int:item_id>', methods=['POST'])
def remove_from_cart(item_id):
    if 'user_id' not in session:
        flash('Please login to manage your cart', 'error')
        return jsonify({'error': 'Authentication required'}), 401
    
    cart_item = CartItem.query.get_or_404(item_id)
    if cart_item.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(cart_item)
    db.session.commit()
    
    return jsonify({'message': 'Removed from cart successfully'})

@app.route('/cart/update/<int:item_id>', methods=['POST'])
def update_cart_quantity(item_id):
    if 'user_id' not in session:
        flash('Please login to update your cart', 'error')
        return jsonify({'error': 'Authentication required'}), 401
    
    cart_item = CartItem.query.get_or_404(item_id)
    if cart_item.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    quantity = data.get('quantity', 1)
    
    if quantity < 1:
        return jsonify({
            'success': False,
            'message': 'Quantity must be at least 1'
        })
    
    if quantity > cart_item.variation.stock:
        return jsonify({
            'success': False,
            'message': f'Maximum available stock is {cart_item.variation.stock}'
        })
    
    cart_item.quantity = quantity
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Cart updated successfully'
    })

# Admin routes
@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Please login as admin', 'error')
        return redirect(url_for('auth'))
    
    users = User.query.filter_by(is_admin=False).all()
    products = Product.query.all()
    
    # Calculate total sales (exclude cancelled/refund orders)
    total_sales = db.session.query(db.func.sum(Order.total_amount))\
        .filter(Order.status.in_(['paid', 'complete']))\
        .filter(~Order.status.in_(['cancelled', 'refund']))\
        .scalar() or 0
    
    # Calculate total products sold (exclude cancelled/refund orders)
    total_sold = db.session.query(db.func.sum(OrderItem.quantity))\
        .join(Order)\
        .filter(Order.status.in_(['paid', 'complete']))\
        .filter(~Order.status.in_(['cancelled', 'refund']))\
        .scalar() or 0
    
    return render_template('admin/dashboard.html', 
                         users=users, 
                         products=products,
                         total_sales=total_sales,
                         total_sold=total_sold)

@app.route('/admin/product_variation/<int:variation_id>/update_stock', methods=['POST'])
def update_product_stock(variation_id):
    if not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.get_json()
    if not data or 'stock' not in data:
        return jsonify({'success': False, 'message': 'Stock value is required'}), 400
    
    try:
        stock = int(data['stock'])
        if stock < 0:
            return jsonify({'success': False, 'message': 'Stock cannot be negative'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid stock value'}), 400
    
    variation = ProductVariation.query.get_or_404(variation_id)
    variation.stock = stock
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Stock updated successfully', 'stock': variation.stock})

@app.route('/admin/user/<int:user_id>')
def get_user_details(user_id):
    if not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        user = User.query.get_or_404(user_id)
        orders = Order.query.filter_by(user_id=user_id).order_by(Order.order_date.desc()).all()
        
        # Format the user data
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name or 'N/A',
            'phone': user.phone or 'N/A',
            'address_line1': user.address_line1 or 'N/A',
            'address_line2': user.address_line2 or 'N/A',
            'city': user.city or 'N/A',
            'province': user.province or 'N/A',
            'postal_code': user.postal_code or 'N/A',
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else 'N/A',
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'N/A'
        }
        
        # Format the orders data
        orders_data = []
        for order in orders:
            order_items = []
            for item in order.items:
                try:
                    order_items.append({
                        'product_name': item.variation.product.name,
                        'size': item.variation.size,
                        'color': item.variation.color,
                        'quantity': item.quantity,
                        'price': item.price
                    })
                except Exception as e:
                    print(f"Error processing order item: {str(e)}")
                    continue
            
            orders_data.append({
                'id': order.id,
                'date': order.order_date.strftime('%Y-%m-%d %H:%M:%S'),
                'status': order.status,
                'total_amount': order.total_amount,
                'payment_method': order.payment_method,  # Add payment method here
                'items': order_items,
                'cancel_refund_reason': order.cancel_refund_reason  # Include the reason here
            })
        
        # Format the cart items data
        cart_items_data = []
        for item in user.cart_items:
            try:
                cart_items_data.append({
                    'product_name': item.variation.product.name,
                    'size': item.variation.size,
                    'color': item.variation.color,
                    'quantity': item.quantity,
                    'price': item.variation.price
                })
            except Exception as e:
                print(f"Error processing cart item: {str(e)}")
                continue
        
        return jsonify({
            'success': True,
            'user': user_data,
            'orders': orders_data,
            'cart_items': cart_items_data
        })
        
    except Exception as e:
        print(f"Error in get_user_details: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to load user details. Please try again.'
        }), 500


# This is a basic example of a decorator that can be used to check if a user is logged in before allowing them to access a certain route.
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('auth'))
        return f(*args, **kwargs)
    return decorated_function

# This decorator can be used to check if a user is an admin before allowing them to access a certain route.
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('Please login as admin to access this page', 'error')
            return redirect(url_for('auth'))
        return f(*args, **kwargs)
    return decorated_function


# Main routes
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/products')
def products():
    products = Product.query.all()
    return render_template('products.html', products=products)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/api/variations/<int:product_id>')
def get_variations(product_id):
    variations = ProductVariation.query.filter_by(product_id=product_id).all()
    return jsonify([variation.to_dict() for variation in variations])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Add sample data if database is empty
        if not Product.query.first():
            # Create admin user
            if not User.query.filter_by(username='admin').first():
                admin = User(username='admin', email='admin@example.com', is_admin=True)
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()

            # Sample products
            products = [
                {
                    "name": "Nike Air Max Comfort",
                    "description": "Premium comfort running shoes with advanced cushioning technology. Perfect for both athletic performance and casual wear. Features Nike's signature Air Max technology for superior comfort and support.",
                    "base_price": 2999.00,
                    "category": "Running",
                    "brand": "Nike",
                    "variations": [
                        {
                            "size": "40",
                            "color": "Black",
                            "price": 2999.00,
                            "stock": 10,
                            "image_url": "https://images.pexels.com/photos/2529148/pexels-photo-2529148.jpeg"
                        },
                        {
                            "size": "41",
                            "color": "Red",
                            "price": 3199.00,
                            "stock": 5,
                            "image_url": "https://images.pexels.com/photos/1598505/pexels-photo-1598505.jpeg"
                        },
                        {
                            "size": "42",
                            "color": "Blue",
                            "price": 3099.00,
                            "stock": 8,
                            "image_url": "https://images.pexels.com/photos/1598508/pexels-photo-1598508.jpeg"
                        }
                    ]
                },
                {
                    "name": "Adidas Ultraboost",
                    "description": "Experience ultimate comfort and energy return with the Adidas Ultraboost. Features responsive Boost cushioning and a Primeknit upper that adapts to your foot's movement.",
                    "base_price": 3499.00,
                    "category": "Running",
                    "brand": "Adidas",
                    "variations": [
                        {
                            "size": "40",
                            "color": "White",
                            "price": 3499.00,
                            "stock": 12,
                            "image_url": "https://images.pexels.com/photos/1159670/pexels-photo-1159670.jpeg"
                        },
                        {
                            "size": "41",
                            "color": "Gray",
                            "price": 3499.00,
                            "stock": 8,
                            "image_url": "https://images.pexels.com/photos/1464625/pexels-photo-1464625.jpeg"
                        }
                    ]
                },
                {
                    "name": "Puma RS-X",
                    "description": "Bold and chunky design meets modern comfort. The Puma RS-X features innovative running system technology and premium cushioning for all-day comfort.",
                    "base_price": 2799.00,
                    "category": "Lifestyle",
                    "brand": "Puma",
                    "variations": [
                        {
                            "size": "41",
                            "color": "White/Blue",
                            "price": 2799.00,
                            "stock": 15,
                            "image_url": "https://images.pexels.com/photos/1240892/pexels-photo-1240892.jpeg"
                        },
                        {
                            "size": "42",
                            "color": "Black/Red",
                            "price": 2899.00,
                            "stock": 10,
                            "image_url": "https://images.pexels.com/photos/1478442/pexels-photo-1478442.jpeg"
                        }
                    ]
                },
                {
                    "name": "Nike Air Jordan 1",
                    "description": "The iconic basketball shoe that started it all. The Air Jordan 1 combines classic style with modern comfort, perfect for both the court and the streets.",
                    "base_price": 3999.00,
                    "category": "Basketball",
                    "brand": "Nike",
                    "variations": [
                        {
                            "size": "41",
                            "color": "Chicago Red",
                            "price": 3999.00,
                            "stock": 5,
                            "image_url": "https://images.pexels.com/photos/1032110/pexels-photo-1032110.jpeg"
                        },
                        {
                            "size": "42",
                            "color": "Royal Blue",
                            "price": 4199.00,
                            "stock": 3,
                            "image_url": "https://images.pexels.com/photos/1456706/pexels-photo-1456706.jpeg"
                        }
                    ]
                }
            ]

            # Add products and their variations
            for product_data in products:
                variations_data = product_data.pop('variations')
                product = Product(**product_data)
                db.session.add(product)
                db.session.commit()

                for variation_data in variations_data:
                    variation = ProductVariation(product_id=product.id, **variation_data)
                    db.session.add(variation)
                db.session.commit()

    app.run(debug=True, port=8000)
