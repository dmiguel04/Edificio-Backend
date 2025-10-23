from django.core.management.base import BaseCommand
from django.conf import settings
import logging

try:
    import stripe
except Exception:
    stripe = None

from apps.finanzas.models import Payment

class Command(BaseCommand):
    help = 'Reconcilia pagos pendientes con Stripe: actualiza estado según PaymentIntent en Stripe.'

    def handle(self, *args, **options):
        logger = logging.getLogger('finanzas.management.reconcile_payments')
        if stripe is None:
            logger.error('stripe library not installed')
            return
        stripe.api_key = getattr(settings, 'STRIPE_SECRET_KEY', None)
        qs = Payment.objects.filter(status__in=['pending', 'requires_payment_method'])
        logger.info('Reconciling %d payments', qs.count())
        for p in qs:
            try:
                if not p.stripe_payment_intent:
                    continue
                intent = stripe.PaymentIntent.retrieve(p.stripe_payment_intent)
                status = intent.get('status') if isinstance(intent, dict) else getattr(intent, 'status', None)
                if status == 'succeeded':
                    p.status = 'succeeded'
                    p.save()
                    logger.info('Payment %s marked succeeded', p.id)
                elif status == 'requires_payment_method':
                    p.status = 'requires_payment_method'
                    p.save()
                elif status == 'canceled':
                    p.status = 'canceled'
                    p.save()
                else:
                    logger.info('Payment %s remains in status %s', p.id, status)
            except Exception as exc:
                logger.exception('Failed to reconcile payment %s: %s', p.id, exc)
