from django.apps import AppConfig


class MsisConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "msis_app"

    def ready(self):
        import msis_app.signals
