function initializeProductDetail(productData) {
    const sizeButtons = document.querySelectorAll('.size-button');
    const colorButtons = document.querySelectorAll('.color-button');
    const addToCartButton = document.getElementById('addToCart');
    const buyNowButton = document.getElementById('buyNow');
    const stockStatus = document.getElementById('stockStatus');
    const mainImage = document.getElementById('mainImage');
    const currentPrice = document.getElementById('currentPrice');
    const quantityInput = document.getElementById('quantity');
    
    let selectedSize = null;
    let selectedColor = null;
    
    function updateProductInfo() {
        if (selectedSize && selectedColor) {
            const variation = productData.variations.find(v => 
                v.size === selectedSize && v.color === selectedColor
            );
            
            if (variation) {
                // Update price
                currentPrice.textContent = variation.price.toFixed(2);
                
                // Update image
                if (variation.image_url) {
                    mainImage.src = variation.image_url;
                }
                
                // Update stock status and buttons
                if (variation.stock > 5) {
                    stockStatus.textContent = 'In Stock';
                    stockStatus.className = 'stock-status text-green-600';
                    addToCartButton.disabled = false;
                    buyNowButton.disabled = false;
                } else if (variation.stock > 0) {
                    stockStatus.textContent = `Only ${variation.stock} left in stock!`;
                    stockStatus.className = 'stock-status text-yellow-600';
                    addToCartButton.disabled = false;
                    buyNowButton.disabled = false;
                } else {
                    stockStatus.textContent = 'Out of Stock';
                    stockStatus.className = 'stock-status text-red-600';
                    addToCartButton.disabled = true;
                    buyNowButton.disabled = true;
                }
            } else {
                stockStatus.textContent = 'This combination is not available';
                stockStatus.className = 'stock-status text-red-600';
                addToCartButton.disabled = true;
                buyNowButton.disabled = true;
            }
        } else {
            addToCartButton.disabled = true;
            buyNowButton.disabled = true;
            stockStatus.textContent = 'Please select size and color';
            stockStatus.className = 'stock-status text-gray-600';
        }
    }
    
    sizeButtons.forEach(button => {
        button.addEventListener('click', function() {
            sizeButtons.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            selectedSize = this.dataset.size;
            updateProductInfo();
        });
    });
    
    colorButtons.forEach(button => {
        button.addEventListener('click', function() {
            colorButtons.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            selectedColor = this.dataset.color;
            updateProductInfo();
        });
    });
    
    // Function to add item to cart and return promise
    function addToCart(redirectToCheckout = false) {
        if (selectedSize && selectedColor) {
            const variation = productData.variations.find(v => 
                v.size === selectedSize && v.color === selectedColor
            );
            
            if (variation) {
                const quantity = parseInt(quantityInput.value) || 1;
                
                return fetch(`/cart/add/${variation.id}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `quantity=${quantity}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        if (data.error === 'Please login first') {
                            window.location.href = '/login';
                            return;
                        }
                        throw new Error(data.error);
                    }
                    
                    if (redirectToCheckout) {
                        window.location.href = '/checkout';
                    } else {
                        alert('Added to cart successfully!');
                    }
                });
            }
        }
        return Promise.reject(new Error('Please select size and color'));
    }

    // Add to cart button click handler
    addToCartButton.addEventListener('click', function() {
        addToCart(false).catch(error => {
            console.error('Error:', error);
            alert(error.message || 'An error occurred while adding to cart');
        });
    });

    // Buy now button click handler
    buyNowButton.addEventListener('click', function() {
        addToCart(true).catch(error => {
            console.error('Error:', error);
            alert(error.message || 'An error occurred while processing your request');
        });
    });
    
    // Tab functionality
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabId = this.dataset.tab;
            
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.add('hidden'));
            
            this.classList.add('active');
            document.getElementById(tabId + 'Content').classList.remove('hidden');
        });
    });

    // Initialize product data
    console.log('Product Data:', productData);
}
