"""
Django app configuration for Security module.
"""
from django.apps import AppConfig


class SecurityConfig(AppConfig):
    """
    Configuration for the Security app.
    """
    name = 'security'
    verbose_name = 'Security'
    
    def ready(self):
        """
        Initialize the app when Django starts.
        """
        # Import signals or perform other initialization
        pass
