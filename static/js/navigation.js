/**
 * HR System Navigation Controller
 * Handles sidebar toggling, responsive behavior, and navigation interactions
 */
(function() {
    // DOM Elements
    const body = document.body;
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebarClose = document.getElementById('sidebarClose');
    const sidebarOverlay = document.querySelector('.sidebar-overlay');
    const sidebarCollapseToggle = document.querySelector('.sidebar-collapse-toggle');
    const dropdownToggles = document.querySelectorAll('.hr-dropdown-toggle');
    const megaMenuToggles = document.querySelectorAll('[data-mega-menu]');
    
    /**
     * Toggle sidebar open/closed state
     */
    function toggleSidebar() {
        body.classList.toggle('sidebar-open');
        
        // Prevent scrolling when sidebar is open on mobile
        if (body.classList.contains('sidebar-open')) {
            document.documentElement.style.overflow = 'hidden';
        } else {
            document.documentElement.style.overflow = '';
        }
    }
    
    /**
     * Toggle sidebar collapsed state (desktop)
     */
    function toggleSidebarCollapse() {
        body.classList.toggle('sidebar-collapsed');
        localStorage.setItem('sidebar-collapsed', body.classList.contains('sidebar-collapsed'));
    }
    
    /**
     * Initialize sidebar state from saved preference
     */
    function initSidebarState() {
        // On mobile, sidebar starts closed
        if (window.innerWidth < 992) {
            body.classList.remove('sidebar-open');
            return;
        }
        
        // On desktop, check for saved preference
        const sidebarCollapsed = localStorage.getItem('sidebar-collapsed') === 'true';
        if (sidebarCollapsed) {
            body.classList.add('sidebar-collapsed');
        } else {
            body.classList.remove('sidebar-collapsed');
        }
    }
    
    /**
     * Handle dropdown toggle in sidebar
     */
    function toggleDropdown(e) {
        e.preventDefault();
        
        const parent = this.closest('.hr-nav-item');
        const dropdown = parent.querySelector('.hr-dropdown');
        const isOpen = dropdown.classList.contains('show');
        
        // Close all open dropdowns first
        document.querySelectorAll('.hr-dropdown.show').forEach(item => {
            if (item !== dropdown) {
                item.classList.remove('show');
                item.style.maxHeight = '0px';
            }
        });
        
        // Toggle current dropdown
        dropdown.classList.toggle('show');
        
        if (!isOpen) {
            dropdown.style.maxHeight = dropdown.scrollHeight + 'px';
        } else {
            dropdown.style.maxHeight = '0px';
        }
        
        // Toggle aria-expanded attribute
        this.setAttribute('aria-expanded', !isOpen);
    }
    
    /**
     * Toggle mega menu
     */
    function toggleMegaMenu(e) {
        e.preventDefault();
        
        const menuId = this.getAttribute('data-mega-menu');
        const menu = document.getElementById(menuId);
        
        if (!menu) return;
        
        // Close other mega menus
        document.querySelectorAll('.mega-menu.show').forEach(item => {
            if (item !== menu) {
                item.classList.remove('show');
            }
        });
        
        // Toggle current menu
        menu.classList.toggle('show');
        
        // Update aria-expanded
        this.setAttribute('aria-expanded', menu.classList.contains('show'));
        
        // Close mega menu when clicking outside
        if (menu.classList.contains('show')) {
            document.addEventListener('click', closeMegaMenuOnClickOutside);
        } else {
            document.removeEventListener('click', closeMegaMenuOnClickOutside);
        }
    }
    
    /**
     * Close mega menu when clicking outside
     */
    function closeMegaMenuOnClickOutside(e) {
        const menu = document.querySelector('.mega-menu.show');
        if (!menu) return;
        
        const menuToggle = document.querySelector(`[data-mega-menu="${menu.id}"]`);
        
        if (!menu.contains(e.target) && !menuToggle.contains(e.target)) {
            menu.classList.remove('show');
            menuToggle.setAttribute('aria-expanded', 'false');
            document.removeEventListener('click', closeMegaMenuOnClickOutside);
        }
    }
    
    /**
     * Handle window resize events
     */
    function handleResize() {
        if (window.innerWidth >= 992) {
            // On desktop
            document.documentElement.style.overflow = '';
            body.classList.remove('sidebar-open');
        } else {
            // On mobile
            if (body.classList.contains('sidebar-open')) {
                document.documentElement.style.overflow = 'hidden';
            }
        }
    }
    
    /**
     * Set up all event listeners
     */
    function setupEventListeners() {
        // Sidebar toggle (mobile)
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', toggleSidebar);
        }
        
        // Sidebar close button
        if (sidebarClose) {
            sidebarClose.addEventListener('click', toggleSidebar);
        }
        
        // Sidebar overlay (closes sidebar when clicked)
        if (sidebarOverlay) {
            sidebarOverlay.addEventListener('click', toggleSidebar);
        }
        
        // Sidebar collapse toggle (desktop)
        if (sidebarCollapseToggle) {
            sidebarCollapseToggle.addEventListener('click', toggleSidebarCollapse);
        }
        
        // Dropdown toggles
        dropdownToggles.forEach(toggle => {
            toggle.addEventListener('click', toggleDropdown);
        });
        
        // Mega menu toggles
        megaMenuToggles.forEach(toggle => {
            toggle.addEventListener('click', toggleMegaMenu);
        });
        
        // Window resize handler
        window.addEventListener('resize', handleResize);
    }
    
    // Initialize sidebar and navigation
    document.addEventListener('DOMContentLoaded', () => {
        initSidebarState();
        setupEventListeners();
        
        // Add active class to current page in nav
        const currentPath = window.location.pathname;
        document.querySelectorAll('.hr-nav-link').forEach(link => {
            if (link.getAttribute('href') === currentPath) {
                link.classList.add('active');
                
                // If in dropdown, expand the dropdown
                const parentDropdown = link.closest('.hr-dropdown');
                if (parentDropdown) {
                    parentDropdown.classList.add('show');
                    parentDropdown.style.maxHeight = parentDropdown.scrollHeight + 'px';
                    
                    // Set aria-expanded on the toggle
                    const toggle = parentDropdown.previousElementSibling;
                    if (toggle && toggle.classList.contains('hr-dropdown-toggle')) {
                        toggle.setAttribute('aria-expanded', 'true');
                    }
                }
            }
        });
    });
})();
