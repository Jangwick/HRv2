/**
 * Enhanced theme management for HR System
 * Handles dark/light mode switching and system preference detection
 * With improved UX/UI and visual feedback
 */
(function() {
    // Theme settings
    const THEME_KEY = 'hr-theme-preference';
    const DARK_THEME_CLASS = 'dark-mode';
    const LIGHT_THEME = 'light';
    const DARK_THEME = 'dark';
    const AUTO_THEME = 'auto';
    
    // DOM selectors
    const themeToggles = document.querySelectorAll('.theme-toggle');
    const floatingThemeToggle = document.getElementById('floatingThemeToggle');
    const floatingToggleContainer = document.querySelector('.floating-theme-toggle');
    const htmlElement = document.documentElement;
    
    // Detect system preference
    const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)');
    
    // Track user scroll to show/hide floating toggle
    let lastScrollTop = 0;
    let scrollTimeout;
    
    /**
     * Apply the specified theme with visual feedback
     */
    function applyTheme(theme) {
        let effectiveTheme = theme;
        
        // Handle 'auto' theme
        if (theme === AUTO_THEME) {
            effectiveTheme = prefersDarkMode.matches ? DARK_THEME : LIGHT_THEME;
            // Update status indicator for auto theme
            document.querySelectorAll('.theme-status').forEach(el => {
                el.style.backgroundColor = '#17a2b8'; // Info color for auto mode
            });
        } else {
            // Update status indicator based on theme
            const statusColor = theme === DARK_THEME ? '#6f42c1' : '#ffc107';
            document.querySelectorAll('.theme-status').forEach(el => {
                el.style.backgroundColor = statusColor;
            });
        }
        
        // Apply theme with transition class for smooth switching
        htmlElement.classList.add('theme-transitioning');
        
        if (effectiveTheme === DARK_THEME) {
            htmlElement.classList.add(DARK_THEME_CLASS);
            document.body.setAttribute('data-bs-theme', 'dark');
            updateThemeIcons(true);
            
            // Flash animation for theme icon
            flashThemeIcon('.theme-icon-light');
        } else {
            htmlElement.classList.remove(DARK_THEME_CLASS);
            document.body.setAttribute('data-bs-theme', 'light');
            updateThemeIcons(false);
            
            // Flash animation for theme icon
            flashThemeIcon('.theme-icon-dark');
        }
        
        // Remove transition class after animation completes
        setTimeout(() => {
            htmlElement.classList.remove('theme-transitioning');
        }, 300);
    }
    
    /**
     * Flash animation for the theme icon
     */
    function flashThemeIcon(selector) {
        const icons = document.querySelectorAll(selector);
        icons.forEach(icon => {
            icon.classList.add('theme-icon-flash');
            setTimeout(() => {
                icon.classList.remove('theme-icon-flash');
            }, 500);
        });
    }
    
    /**
     * Get the current saved theme
     */
    function getSavedTheme() {
        return localStorage.getItem(THEME_KEY) || AUTO_THEME;
    }
    
    /**
     * Save theme preference to localStorage
     */
    function saveThemePreference(theme) {
        localStorage.setItem(THEME_KEY, theme);
        applyTheme(theme);
    }
    
    /**
     * Toggle between light and dark mode (for quick toggle button)
     */
    function quickToggleTheme() {
        const currentTheme = getSavedTheme();
        // If current theme is auto, check what's actually applied
        if (currentTheme === AUTO_THEME) {
            const isDark = prefersDarkMode.matches;
            saveThemePreference(isDark ? LIGHT_THEME : DARK_THEME);
        } else {
            saveThemePreference(currentTheme === DARK_THEME ? LIGHT_THEME : DARK_THEME);
        }
        
        // Update active state on theme toggles
        updateActiveState();
    }
    
    /**
     * Update theme toggle icons
     */
    function updateThemeIcons(isDark) {
        document.querySelectorAll('.theme-icon-light').forEach(el => {
            el.style.display = isDark ? 'inline-block' : 'none';
        });
        document.querySelectorAll('.theme-icon-dark').forEach(el => {
            el.style.display = isDark ? 'none' : 'inline-block';
        });
    }
    
    /**
     * Update active state on theme toggles
     */
    function updateActiveState() {
        const savedTheme = getSavedTheme();
        themeToggles.forEach(toggle => {
            toggle.classList.remove('active');
            if (toggle.getAttribute('data-theme-value') === savedTheme) {
                toggle.classList.add('active');
            }
        });
    }
    
    /**
     * Initialize theme based on saved preference or system preference
     */
    function initializeTheme() {
        const savedTheme = getSavedTheme();
        applyTheme(savedTheme);
        updateActiveState();
    }
    
    /**
     * Handle scroll events to show/hide floating theme toggle
     */
    function handleScroll() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        // Show floating toggle when scrolling down past a threshold
        if (scrollTop > 300 && scrollTop > lastScrollTop) {
            floatingToggleContainer.classList.add('show');
        } else {
            floatingToggleContainer.classList.remove('show');
        }
        
        lastScrollTop = scrollTop;
        
        // Hide after a delay of no scrolling
        clearTimeout(scrollTimeout);
        scrollTimeout = setTimeout(() => {
            floatingToggleContainer.classList.remove('show');
        }, 3000);
    }
    
    /**
     * Set up event listeners
     */
    function setupEventListeners() {
        // Theme toggle buttons (in dropdown)
        themeToggles.forEach(toggle => {
            toggle.addEventListener('click', function(e) {
                e.preventDefault();
                const themeValue = this.getAttribute('data-theme-value');
                saveThemePreference(themeValue);
                updateActiveState();
                
                // Provide a subtle feedback that the theme was changed
                const feedbackEffect = document.createElement('div');
                feedbackEffect.className = 'theme-feedback-effect';
                this.appendChild(feedbackEffect);
                setTimeout(() => feedbackEffect.remove(), 500);
            });
        });
        
        // Floating quick toggle button
        if (floatingThemeToggle) {
            floatingThemeToggle.addEventListener('click', function(e) {
                e.preventDefault();
                quickToggleTheme();
                
                // Add pulsing effect on click
                this.classList.add('pulse-effect');
                setTimeout(() => {
                    this.classList.remove('pulse-effect');
                }, 500);
            });
        }
        
        // Listen for system preference changes
        prefersDarkMode.addEventListener('change', (e) => {
            if (getSavedTheme() === AUTO_THEME) {
                applyTheme(AUTO_THEME);
            }
        });
        
        // Listen for scroll events to show/hide floating toggle
        window.addEventListener('scroll', handleScroll);
    }
    
    // Initialize theme on page load
    document.addEventListener('DOMContentLoaded', () => {
        initializeTheme();
        setupEventListeners();
    });
})();
