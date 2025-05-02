from django.apps import AppConfig

class Checksheet1Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'  # optional but recommended
    name = 'checksheet1'

    def ready(self):
        import checksheet1.signals
