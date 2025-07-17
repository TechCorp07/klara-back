# apps.py in healthcare app

from django.apps import AppConfig


class HealthcareConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'healthcare'
    verbose_name = 'Klararety Healthcare'

    def ready(self):
        # Import signals
        import healthcare.signals
