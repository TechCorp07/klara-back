from django.apps import AppConfig


class ReportsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'reports'
    verbose_name = 'Klararety Reports & Analytics'

    def ready(self):
        """Register signals when app is ready."""
        import reports.signals  # Import signals module
