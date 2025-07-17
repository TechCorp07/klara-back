from django.apps import AppConfig


class FHIRConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'fhir'
    verbose_name = 'FHIR Integration'

    def ready(self):
        """
        Initialize signals and other setup when the app is ready.
        """
        # import fhir.signals  # noqa
