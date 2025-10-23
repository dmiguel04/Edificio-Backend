from django.core.management.base import BaseCommand
from django.conf import settings
from apps.finanzas.models import Payment
import stripe

class Command(BaseCommand):
    help = 'Reconcile pending payments with Stripe PaymentIntents'

    def handle(self, *args, **options):
        stripe.api_key = getattr(settings, 'STRIPE_SECRET_KEY', None)
        pending = Payment.objects.filter(status='pending')
        self.stdout.write(f'Found {pending.count()} pending payments')
        for p in pending:
            from django.core.management.base import BaseCommand
            from django.conf import settings
            from apps.finanzas.models import Payment
            import stripe


            class Command(BaseCommand):
                help = 'Reconcile pending payments with Stripe PaymentIntents'

                def handle(self, *args, **options):
                    stripe.api_key = getattr(settings, 'STRIPE_SECRET_KEY', None)
                    pending = Payment.objects.filter(status='pending')
                    self.stdout.write(f'Found {pending.count()} pending payments')
                    for p in pending:
                        try:
                            intent = stripe.PaymentIntent.retrieve(p.stripe_payment_intent)
                            status = intent.get('status')
                            self.stdout.write(f'Payment {p.id} intent {p.stripe_payment_intent} status {status}')
                            if status in ('succeeded', 'requires_capture'):
                                p.status = 'succeeded'
                                p.save()
                        except Exception as e:
                            self.stderr.write(f'Failed retrieving {p.stripe_payment_intent}: {e}')