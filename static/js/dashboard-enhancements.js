/**
 * Dashboard UI Enhancements
 * Adds interactive charts, live updates, and interactive elements
 */

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize stat counters with animation
    initCounters();
    
    // Initialize any charts
    initCharts();
    
    // Add item hover effects
    initHoverEffects();
});

/**
 * Animates number counters for statistics
 */
function initCounters() {
    const counters = document.querySelectorAll('.counter-value');
    
    counters.forEach(counter => {
        const target = parseInt(counter.getAttribute('data-target'));
        const duration = 1500; // animation duration in ms
        const step = target / (duration / 16); // 60fps
        
        let current = 0;
        const updateCounter = () => {
            current += step;
            if (current < target) {
                counter.textContent = Math.ceil(current);
                requestAnimationFrame(updateCounter);
            } else {
                counter.textContent = target;
            }
        };
        
        // Start animation when element is in viewport
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    updateCounter();
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });
        
        observer.observe(counter);
    });
}

/**
 * Initialize charts if Chart.js is available
 */
function initCharts() {
    if (typeof Chart !== 'undefined') {
        // Employee distribution chart
        if (document.getElementById('employeeDistributionChart')) {
            const ctx = document.getElementById('employeeDistributionChart').getContext('2d');
            
            // Use system colors that work with light/dark themes
            const chartColors = [
                getComputedStyle(document.documentElement).getPropertyValue('--bs-primary'),
                getComputedStyle(document.documentElement).getPropertyValue('--bs-info'),
                getComputedStyle(document.documentElement).getPropertyValue('--bs-success'),
                getComputedStyle(document.documentElement).getPropertyValue('--bs-warning'),
                getComputedStyle(document.documentElement).getPropertyValue('--bs-danger')
            ];
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: departmentData.labels,
                    datasets: [{
                        data: departmentData.values,
                        backgroundColor: chartColors,
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }
    }
}

/**
 * Add hover and interaction effects
 */
function initHoverEffects() {
    const cards = document.querySelectorAll('.stat-card, .info-card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.classList.add('active');
        });
        
        card.addEventListener('mouseleave', function() {
            this.classList.remove('active');
        });
    });
}

/**
 * Show loading skeleton for async content
 * @param {string} selector - Element selector to replace with skeleton
 * @param {number} count - Number of skeleton items
 */
function showLoadingSkeleton(selector, count = 1) {
    const container = document.querySelector(selector);
    if (!container) return;
    
    let skeletonHTML = '';
    for (let i = 0; i < count; i++) {
        skeletonHTML += `
            <div class="skeleton-item mb-3 p-3">
                <div class="skeleton mb-2" style="height: 20px; width: 70%;"></div>
                <div class="skeleton" style="height: 15px; width: 90%;"></div>
                <div class="skeleton mt-1" style="height: 15px; width: 60%;"></div>
            </div>
        `;
    }
    
    container.innerHTML = skeletonHTML;
}

/**
 * Adds ripple effect to buttons
 */
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('ripple-effect') || 
        e.target.closest('.ripple-effect')) {
        
        const button = e.target.classList.contains('ripple-effect') ? 
                       e.target : 
                       e.target.closest('.ripple-effect');
        
        const ripple = document.createElement('span');
        const rect = button.getBoundingClientRect();
        
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        ripple.style.width = ripple.style.height = `${size}px`;
        ripple.style.left = `${x}px`;
        ripple.style.top = `${y}px`;
        ripple.classList.add('ripple');
        
        button.appendChild(ripple);
        
        setTimeout(() => {
            ripple.remove();
        }, 600);
    }
});
