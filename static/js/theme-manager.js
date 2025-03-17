/**
 * Theme Manager
 * Manages theme switching between light, dark, and system preference
 */
(function() {
  // Constants
  const THEME_KEY = 'hr-theme-preference';
  const DARK_MODE_CLASS = 'dark-mode';
  const LIGHT_THEME = 'light';
  const DARK_THEME = 'dark';
  const SYSTEM_THEME = 'auto';
  
  // Detect system preference
  const prefersDarkScheme = window.matchMedia("(prefers-color-scheme: dark)");
  
  /**
   * Get current theme from localStorage or default to system preference
   */
  function getCurrentTheme() {
    return localStorage.getItem(THEME_KEY) || SYSTEM_THEME;
  }
  
  /**
   * Apply theme to document
   * @param {string} theme - The theme to apply: 'light', 'dark', or 'auto'
   */
  function applyTheme(theme) {
    // If theme is auto, determine from system preference
    const isDark = theme === SYSTEM_THEME 
      ? prefersDarkScheme.matches 
      : theme === DARK_THEME;
    
    // Apply appropriate classes and attributes
    if (isDark) {
      document.documentElement.classList.add(DARK_MODE_CLASS);
      document.documentElement.setAttribute('data-bs-theme', 'dark');
    } else {
      document.documentElement.classList.remove(DARK_MODE_CLASS);
      document.documentElement.setAttribute('data-bs-theme', 'light');
    }
    
    // Update active state on toggle buttons
    updateToggleStates(theme);
    
    // Dispatch event for other components that might need to react to theme changes
    document.dispatchEvent(new CustomEvent('themeChanged', { 
      detail: { theme: theme, isDark: isDark } 
    }));
  }
  
  /**
   * Save theme preference to localStorage
   * @param {string} theme - The theme to save
   */
  function saveTheme(theme) {
    localStorage.setItem(THEME_KEY, theme);
    applyTheme(theme);
  }
  
  /**
   * Update active state on theme toggle buttons
   * @param {string} activeTheme - Currently active theme
   */
  function updateToggleStates(activeTheme) {
    // Remove active class from all theme toggles
    document.querySelectorAll('.theme-toggle').forEach(btn => {
      btn.setAttribute('aria-pressed', 'false');
      btn.classList.remove('active');
      
      // Set active state on the current theme's button
      if (btn.dataset.theme === activeTheme) {
        btn.setAttribute('aria-pressed', 'true');
        btn.classList.add('active');
      }
    });
  }
  
  /**
   * Initialize the theme system
   */
  function initTheme() {
    const savedTheme = getCurrentTheme();
    applyTheme(savedTheme);
    
    // Set up event listeners for theme toggle buttons
    document.querySelectorAll('.theme-toggle').forEach(btn => {
      btn.addEventListener('click', function() {
        const theme = this.dataset.theme;
        saveTheme(theme);
      });
    });
    
    // Listen for system preference changes
    prefersDarkScheme.addEventListener('change', function(e) {
      if (getCurrentTheme() === SYSTEM_THEME) {
        applyTheme(SYSTEM_THEME);
      }
    });
  }
  
  // Initialize on DOM content loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTheme);
  } else {
    initTheme();
  }
  
  // Export functions for potential external use
  window.themeManager = {
    getCurrentTheme,
    applyTheme,
    saveTheme
  };
})();
