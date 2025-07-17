# security/apps.py
from django.apps import AppConfig


class SecurityConfig(AppConfig):
    """
    Configuration for the Security app.
    """
    name = 'security'
    verbose_name = 'Security Management'
    default_auto_field = 'django.db.models.BigAutoField'
    
    def ready(self):
        """
        Initialize the app when Django starts.
        """
        # Import signal handlers
        try:
            from . import signals  # If you create signals
        except ImportError:
            pass
        
        # Initialize security services
        self._initialize_security_services()
    
    def _initialize_security_services(self):
        """Initialize security monitoring services."""
        try:
            # Start background monitoring if configured
            from django.conf import settings
            
            if getattr(settings, 'SECURITY_AUTO_START_MONITORING', False):
                # Initialize monitoring services
                pass
                
        except Exception as e:
            import logging
            logger = logging.getLogger('security')
            logger.error(f"Error initializing security services: {str(e)}")