from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'
    verbose_name = 'Klararety Users'

    def ready(self):
        import users.signals  # Ensures profile creation is triggered on user creation
