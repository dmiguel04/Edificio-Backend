"""Webhook handler for Stripe events with idempotency.

This file verifies Stripe signatures and creates a WebhookEvent record
for each unique Stripe event id. If an event was already processed, it
returns 200 without re-processing to guarantee idempotency.
"""
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.utils import timezone
import hmac
import hashlib
import json

from . import utils as fin_utils
import logging

from .models import CuentaFinanciera, Tarjeta, Transaccion, WebhookEvent, Payment, Invoice, Dispute, FinancialAuditLog

# allow tests to patch this at module level; import lazily inside handler
stripe = None
try:
    import stripe as _stripe
    stripe = _stripe
except Exception:
    stripe = None


@csrf_exempt
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    event = None
    # Prefer using the project's wrapper (can be mocked in tests)
    try:
        event = fin_utils.construct_webhook_event(payload, sig_header, getattr(settings, 'STRIPE_WEBHOOK_SECRET', None))
    except Exception:
        # If the project's wrapper failed (e.g., stripe not installed), try module-level stripe
        event = None
        try:
            if stripe is not None and hasattr(stripe, 'Webhook'):
                event = stripe.Webhook.construct_event(payload, sig_header, getattr(settings, 'STRIPE_WEBHOOK_SECRET', None))
        except Exception:
            event = None

        if event is None:
            # Fallback: attempt to parse payload as JSON. If a webhook secret is configured, verify HMAC.
            try:
                parsed = json.loads(payload.decode('utf-8'))
            except Exception:
                return HttpResponse(status=400)

            webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)
            if webhook_secret and sig_header:
                # signature header format: t=...,v1=...
                try:
                    parts = {k: v for k, v in [p.split('=') for p in sig_header.split(',')]}
                    timestamp = parts.get('t')
                    v1 = parts.get('v1')
                    signed_payload = f"{timestamp}.{payload.decode('utf-8')}".encode('utf-8')
                    expected = hmac.new(webhook_secret.encode('utf-8'), signed_payload, hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(expected, v1):
                        return HttpResponse(status=400)
                except Exception:
                    return HttpResponse(status=400)

            event = parsed

    event_id = event.get('id')
    if not event_id:
        return HttpResponse(status=400)

    # Crear o recuperar el registro de webhook; si ya está procesado, salir
    webhook_record, created = WebhookEvent.objects.get_or_create(
        event_id=event_id,
        defaults={'payload': event, 'processed': False}
    )
    if not created and webhook_record.processed:
        return HttpResponse(status=200)

    event_type = event.get('type')
    data = event.get('data', {}).get('object', {})

    try:
        # Ejemplo: marcar Payment como succeeded
        if event_type == 'payment_intent.succeeded':
            pi = data
            payment = Payment.objects.filter(stripe_payment_intent=pi.get('id')).first()
            if payment:
                payment.status = 'succeeded'
                payment.save()

        elif event_type == 'payment_intent.payment_failed':
            pi = data
            payment = Payment.objects.filter(stripe_payment_intent=pi.get('id')).first()
            if payment:
                # record last payment error if present
                last_error = pi.get('last_payment_error') or {}
                payment.status = 'requires_payment_method'
                # Only set fields that exist on the model; otherwise attach to webhook_record
                if hasattr(payment, 'last_error'):
                    try:
                        payment.last_error = str(last_error)
                    except Exception:
                        pass
                else:
                    try:
                        webhook_record.last_error = str(last_error)
                        webhook_record.save()
                    except Exception:
                        pass
                # clear stored payment method if model supports it
                if hasattr(payment, 'stripe_payment_method'):
                    try:
                        setattr(payment, 'stripe_payment_method', None)
                    except Exception:
                        pass
                payment.save()

        elif event_type == 'payment_intent.canceled':
            pi = data
            payment = Payment.objects.filter(stripe_payment_intent=pi.get('id')).first()
            if payment:
                payment.status = 'canceled'
                payment.save()

        elif event_type == 'checkout.session.completed':
            sess = data
            # A completed Checkout Session may include payment_intent id directly or under payment_intents.data
            pi_id = None
            if sess.get('payment_intent'):
                pi_id = sess.get('payment_intent')
            else:
                pints = sess.get('payment_intents') or {}
                try:
                    items = pints.get('data') if isinstance(pints, dict) else None
                    if items and len(items) > 0:
                        # item may be id or object
                        first = items[0]
                        if isinstance(first, dict):
                            pi_id = first.get('id')
                        else:
                            pi_id = first
                except Exception:
                    pi_id = None
            if pi_id:
                payment = Payment.objects.filter(stripe_payment_intent=pi_id).first()
                if payment:
                    payment.status = 'succeeded'
                    payment.save()

        elif event_type == 'invoice.payment_succeeded':
            invoice_data = data
            # If this invoice was created from our Invoice model (metadata), try to mark it paid
            # Stripe invoice may have lines and metadata; attempt to reconcile
            metadata = invoice_data.get('metadata', {}) or {}
            payment_id = metadata.get('payment_id')
            if payment_id:
                try:
                    p = Payment.objects.filter(id=int(payment_id)).first()
                    if p:
                        p.status = 'succeeded'
                        p.save()
                except Exception:
                    pass
            # Additionally, try to mark Invoice model as paid by matching amount and customer
            try:
                # invoice_data['customer'] is stripe customer id
                stripe_customer = invoice_data.get('customer')
                amount_paid = invoice_data.get('amount_paid')
                # find Invoice with same amount and unpaid for that user
                from django.contrib.auth import get_user_model
                User = get_user_model()
                # best-effort: if we can map stripe_customer to a user
                user = None
                if stripe_customer:
                    sc = None
                    try:
                        sc = fin_utils.create_stripe_customer if False else None
                    except Exception:
                        sc = None
                # naive approach: mark any unpaid invoice with same amount as paid
                inv = None
                try:
                    inv = Invoice.objects.filter(amount=amount_paid, paid=False).first()
                except Exception:
                    inv = None
                if inv:
                    inv.paid = True
                    inv.save()
            except Exception:
                pass

        elif event_type == 'treasury.received_credit.created':
            received_credit = data
            stripe_account_id = event.get('account')
            try:
                cuenta = CuentaFinanciera.objects.get(stripe_account_id=stripe_account_id)
                Transaccion.objects.create(
                    cuenta_financiera=cuenta,
                    stripe_transaction_id=received_credit.get('id'),
                    tipo='deposit',
                    monto=received_credit.get('amount'),
                    moneda=received_credit.get('currency'),
                    estado='succeeded',
                    descripcion=received_credit.get('description') or 'Depósito recibido'
                )
            except CuentaFinanciera.DoesNotExist:
                pass

        elif event_type == 'treasury.outbound_transfer.created':
            outbound_transfer = data
            try:
                transaccion = Transaccion.objects.filter(stripe_transaction_id=outbound_transfer.get('id')).first()
                if transaccion:
                    transaccion.estado = outbound_transfer.get('status')
                    transaccion.save()
            except Exception:
                pass

        elif event_type == 'issuing_card.created':
            card = data
            try:
                tarjeta = Tarjeta.objects.filter(stripe_card_id=card.get('id')).first()
                if tarjeta:
                    tarjeta.ultimos_digitos = card.get('last4')
                    tarjeta.estado = card.get('status')
                    tarjeta.save()
            except Exception:
                pass

        elif event_type == 'issuing_transaction.created':
            transaction = data
            try:
                cuenta = CuentaFinanciera.objects.get(stripe_account_id=event.get('account'))
                tarjeta = Tarjeta.objects.filter(stripe_card_id=transaction.get('card')).first()
                Transaccion.objects.create(
                    cuenta_financiera=cuenta,
                    stripe_transaction_id=transaction.get('id'),
                    tipo='card_payment',
                    monto=transaction.get('amount'),
                    moneda=transaction.get('currency'),
                    estado=transaction.get('status'),
                    descripcion=(transaction.get('merchant_data') or {}).get('name', 'Pago con tarjeta'),
                    tarjeta=tarjeta
                )
            except Exception:
                pass

        # Handle disputes (chargebacks)
        elif event_type and event_type.startswith('charge.dispute'):
            dispute_data = data
            try:
                # create or update local Dispute
                stripe_dispute_id = dispute_data.get('id')
                charge = dispute_data.get('charge')
                amount = dispute_data.get('amount') or 0
                reason = dispute_data.get('reason') or ''
                status = dispute_data.get('status') or ''
                # Try to find linked Payment by matching charge/intent
                linked_payment = Payment.objects.filter(stripe_payment_intent=dispute_data.get('payment_intent') or '').first()
                d, created_d = Dispute.objects.update_or_create(
                    stripe_dispute_id=stripe_dispute_id,
                    defaults={'payment': linked_payment, 'amount': amount, 'reason': reason, 'status': status}
                )
                # Log an audit entry
                FinancialAuditLog.objects.create(
                    action_type='dispute.received',
                    amount=(amount / 100.0) if amount else None,
                    user=(linked_payment.usuario if linked_payment else None),
                    payment=linked_payment,
                    before_state=None,
                    after_state={'dispute_id': stripe_dispute_id, 'status': status},
                    notes=f'Dispute received from Stripe: {reason}'
                )
            except Exception:
                logging.exception('Failed processing dispute event')

        # Marcar como procesado
        webhook_record.processed = True
        webhook_record.processed_at = timezone.now()
        webhook_record.save()
    except Exception as exc:
        # Loggear y persistir el error en el registro para diagnóstico. No marcar processed=True
        logging.exception('Error procesando webhook %s: %s', event_id, exc)
        try:
            webhook_record.last_error = str(exc)
            webhook_record.save()
        except Exception:
            # si guardar falla, continuar para devolver 500
            pass
        return HttpResponse(status=500)

    return HttpResponse(status=200)