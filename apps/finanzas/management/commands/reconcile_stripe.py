from django.core.management.base import BaseCommand
from django.conf import settings
from apps.finanzas.models import Payment, FinancialAuditLog
import logging


class Command(BaseCommand):
    help = 'Reconcile pending payments with Stripe PaymentIntents'

    def add_arguments(self, parser):
        parser.add_argument('--force', action='store_true', help='Force update even for non-pending')
        parser.add_argument('--dry-run', action='store_true', help='Do not persist changes, only show what would change')

    def handle(self, *args, **options):
        try:
            import stripe
        except Exception:
            stripe = None

        if stripe is None:
            self.stderr.write('stripe library not installed in the current environment. Install it with: python -m pip install stripe')
            return

        stripe.api_key = getattr(settings, 'STRIPE_SECRET_KEY', None)
        qs = Payment.objects.all() if options.get('force') else Payment.objects.filter(status='pending')
        pending = qs.exclude(stripe_payment_intent__isnull=True).exclude(stripe_payment_intent__startswith='manual-')
        self.stdout.write(f'Found {pending.count()} payments to check')
        changed = 0
        for p in pending:
            try:
                intent = stripe.PaymentIntent.retrieve(p.stripe_payment_intent)
                status = intent.get('status') if isinstance(intent, dict) else getattr(intent, 'status', None)
                self.stdout.write(f'Payment {p.id} intent {p.stripe_payment_intent} status {status}')
                before = {'status': p.status}
                updated = False
                if status in ('succeeded', 'requires_capture') and p.status != 'succeeded':
                    if not options.get('dry_run'):
                        p.status = 'succeeded'
                        p.save()
                    updated = True
                elif status in ('requires_payment_method', 'requires_action') and p.status != 'pending':
                    if not options.get('dry_run'):
                        p.status = 'pending'
                        p.save()
                    updated = True

                if updated:
                    changed += 1
                    if not options.get('dry_run'):
                        FinancialAuditLog.objects.create(
                            action_type='reconcile.update_status',
                            amount=(p.amount / 100.0) if p.amount else None,
                            user=p.usuario,
                            payment=p,
                            before_state=before,
                            after_state={'status': p.status},
                            notes=f'Updated from Stripe status {status}'
                        )
            except Exception as e:
                logging.exception('Failed retrieving %s: %s', p.stripe_payment_intent, e)
                self.stderr.write(f'Failed retrieving {p.stripe_payment_intent}: {e}')
        self.stdout.write(f'Processed {pending.count()} payments, {changed} would be changed{ " (dry-run)" if options.get("dry_run") else "" }')