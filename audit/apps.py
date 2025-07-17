from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'audit'
    verbose_name = 'HIPAA Audit & Compliance'

    def ready(self):
        # Import signal handlers
        import audit.signals
