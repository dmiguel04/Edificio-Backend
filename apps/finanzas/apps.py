from django.apps import AppConfig


class FinanzasConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.finanzas'
    verbose_name = 'Finanzas'
    
    def ready(self):
        # initialize stripe if available using settings
        try:
            from django.conf import settings
            import stripe
            stripe.api_key = getattr(settings, 'STRIPE_SECRET_KEY', None)
        except Exception:
            # stripe may not be installed in some dev/test environments
            pass
