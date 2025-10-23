try:
    import stripe
except ImportError:
    stripe = None
from django.conf import settings


def get_stripe_api_key():
    return getattr(settings, 'STRIPE_SECRET_KEY', None)


def create_stripe_customer(email, name):
    if stripe is None:
        raise RuntimeError('stripe library not installed')
    stripe.api_key = get_stripe_api_key()
    return stripe.Customer.create(email=email, name=name)


def create_payment_intent(amount, currency, customer_id):
    if stripe is None:
        raise RuntimeError('stripe library not installed')
    stripe.api_key = get_stripe_api_key()
    return stripe.PaymentIntent.create(
        amount=amount,
        currency=currency,
        customer=customer_id,
        automatic_payment_methods={'enabled': True},
    )


def create_payment_intent_with_metadata(amount, currency, customer_id, metadata=None, payment_method_types=None, **extra):
    """Create a PaymentIntent and attach metadata (e.g., internal payment_id)."""
    if stripe is None:
        raise RuntimeError('stripe library not installed')
    stripe.api_key = get_stripe_api_key()
    kwargs = dict(
        amount=amount,
        currency=currency,
        customer=customer_id,
        # By default allow automatic methods unless caller specifies explicit types
        automatic_payment_methods={'enabled': True} if payment_method_types is None else None,
    )
    if metadata:
        kwargs['metadata'] = metadata
    # If caller provided explicit payment_method_types, set them and remove automatic
    if payment_method_types is not None:
        # ensure it's a list
        kwargs.pop('automatic_payment_methods', None)
        kwargs['payment_method_types'] = list(payment_method_types)
    else:
        # leave automatic set
        pass
    # Remove None values
    kwargs = {k: v for k, v in kwargs.items() if v is not None}
    # Merge extra options (confirm, return_url, etc.)
    if extra:
        kwargs.update(extra)
    return stripe.PaymentIntent.create(**kwargs)


def create_checkout_session(line_items, success_url, cancel_url, mode='payment', customer=None, metadata=None, ui_mode=None, **extra):
    """Create a Stripe Checkout Session. line_items is a list of dicts as stripe expects.

    Accepts optional `ui_mode` (e.g., 'embedded') and any extra kwargs which will be
    forwarded to stripe.checkout.Session.create. This keeps compatibility and allows
    the view to request embedded Checkout or other new params without changing utils again.
    """
    if stripe is None:
        raise RuntimeError('stripe library not installed')
    stripe.api_key = get_stripe_api_key()
    kwargs = dict(
        payment_method_types=['card'],
        line_items=line_items,
        mode=mode,
        success_url=success_url,
        cancel_url=cancel_url,
    )
    if customer:
        kwargs['customer'] = customer
    if metadata:
        kwargs['metadata'] = metadata
    # allow ui_mode and other extra parameters to be passed through
    if ui_mode:
        kwargs['ui_mode'] = ui_mode
    if extra:
        kwargs.update(extra)
    return stripe.checkout.Session.create(**kwargs)


def create_product(name, description=None):
    if stripe is None:
        raise RuntimeError('stripe library not installed')
    stripe.api_key = get_stripe_api_key()
    return stripe.Product.create(name=name, description=description or '')


def create_price(product_id, unit_amount, currency='usd', recurring=None):
    if stripe is None:
        raise RuntimeError('stripe library not installed')
    stripe.api_key = get_stripe_api_key()
    params = dict(product=product_id, unit_amount=unit_amount, currency=currency)
    if recurring:
        params['recurring'] = recurring
    return stripe.Price.create(**params)


def create_subscription(customer_id, price_id):
    if stripe is None:
        raise RuntimeError('stripe library not installed')
    stripe.api_key = get_stripe_api_key()
    return stripe.Subscription.create(customer=customer_id, items=[{'price': price_id}])


def safe_stripe_call(fn, *args, **kwargs):
    """Wrapper to call stripe functions and handle common Stripe exceptions."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        # Optionally, you could parse stripe.error.* exceptions
        raise


def create_refund(payment_intent_id, amount=None):
    if stripe is None:
        raise RuntimeError('stripe library not installed')
    stripe.api_key = get_stripe_api_key()
    params = {'payment_intent': payment_intent_id}
    if amount:
        params['amount'] = amount
    return stripe.Refund.create(**params)



def construct_webhook_event(payload, sig_header, webhook_secret):
    if stripe is None:
        raise RuntimeError('stripe library not installed')
    stripe.api_key = get_stripe_api_key()
    if webhook_secret:
        return stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    return stripe.Event.construct_from(payload, stripe.api_key)


# --- Additional helpers: risk, retries, metrics, caching ---
# Note: removed Celery import/decorator here; `check_expiring_cards` is a regular
# function that can be invoked from a management command, cron, systemd timer,
# django-crontab or any scheduler. See module bottom for instructions.

import logging
from django.core.cache import cache
import importlib
from django.core.mail import send_mail




def evaluate_payment_risk(payment_intent, user_data=None):
    """Lightweight risk heuristic. Returns an integer risk score."""
    score = 0
    try:
        amount = getattr(payment_intent, 'amount', None) or (payment_intent.get('amount') if isinstance(payment_intent, dict) else None)
        if amount and int(amount) > 1_000_00:  # > $1,000
            score += 2
        # IP vs billing country heuristic
        if user_data:
            ip_country = user_data.get('ip_country')
            billing_country = user_data.get('billing_country')
            if ip_country and billing_country and ip_country != billing_country:
                score += 1
    except Exception:
        logging.exception('evaluate_payment_risk failed')
    return score


def retry_payment(payment):
    """Attempt a simple retry: retrieve PaymentIntent and if status indicates success, update local payment.
    This is a best-effort helper and should be invoked from a task/command.
    """
    try:
        if stripe is None:
            logging.warning('stripe not installed, cannot retry payment')
            return False
        stripe.api_key = get_stripe_api_key()
        if not payment.stripe_payment_intent:
            return False
        intent = stripe.PaymentIntent.retrieve(payment.stripe_payment_intent)
        status = intent.get('status') if isinstance(intent, dict) else getattr(intent, 'status', None)
        if status in ('succeeded', 'requires_capture'):
            payment.status = 'succeeded'
            payment.save()
            return True
    except Exception:
        logging.exception('retry_payment failed for %s', getattr(payment, 'id', None))
    return False


def track_payment_metrics(payment):
    """Very small metrics shim: logs counters for later integration with a metrics backend."""
    try:
        logging.info('metric:payments.total 1')
        logging.info(f"metric:payments.status.{payment.status} 1")
        logging.info(f"metric:payments.amount {getattr(payment, 'amount', 0)}")
    except Exception:
        logging.exception('track_payment_metrics failed')


def get_customer_payment_methods(customer_id, force_refresh=False):
    """Return cached payment methods for a Stripe customer, fallback to Stripe call if needed.
    Cache duration: 1 hour.
    """
    cache_key = f'customer_payment_methods:{customer_id}'
    try:
        if not force_refresh:
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
    except Exception:
        # cache may not be configured; continue
        pass

    if stripe is None:
        return []
    try:
        stripe.api_key = get_stripe_api_key()
        pm_list = stripe.PaymentMethod.list(customer=customer_id, type='card')
        methods = pm_list.data if hasattr(pm_list, 'data') else (pm_list.get('data') if isinstance(pm_list, dict) else [])
        try:
            cache.set(cache_key, methods, 3600)
        except Exception:
            pass
        return methods
    except Exception:
        logging.exception('get_customer_payment_methods failed')
        return []


# --- Monitoring and compliance helpers ---
def create_alert_rule(name, condition, severity='warning'):
    """Create an alert rule in the configured monitoring system.
    This is a no-op stub unless a real monitoring client is configured.
    """
    try:
        # If you have a monitoring client configured in settings, call it
        client = getattr(settings, 'MONITORING_CLIENT', None)
        if client and hasattr(client, 'create_alert'):
            client.create_alert(name=name, condition=condition, severity=severity)
            return True
    except Exception:
        logging.exception('create_alert_rule failed')
    # Fallback: log the rule
    logging.info('Alert rule (stub): %s %s %s', name, condition, severity)
    return False


def setup_payment_monitoring():
    """Configure a few sensible alert rules for payments."""
    create_alert_rule('high_decline_rate', 'payment_decline_rate > 0.15', 'critical')
    create_alert_rule('large_transaction', 'payment_amount > 10000', 'warning')
    create_alert_rule('stripe_api_errors', 'error_count > 5 in 5m', 'critical')
    return True


def log_pii_access(user, payment_data, purpose, request=None):
    """Record access to PII for compliance reasons."""
    try:
        from .models import ComplianceLog
        ip = None
        if request:
            ip = request.META.get('REMOTE_ADDR')
        ComplianceLog.objects.create(
            user=(user if hasattr(user, 'pk') else None),
            data_accessed=str(payment_data)[:2000],
            purpose=purpose,
            ip_address=ip
        )
    except Exception:
        logging.exception('log_pii_access failed')
        return False
    return True


def create_support_ticket_for_payment_issue(payment, issue_type, description):
    """Create a support ticket in the external ticket system if configured.
    Fallback: send an email to support and write the ticket id into payment.support_ticket_id.
    """
    try:
        ticket_id = None
        # Try dynamic import of optional ticket system client
        try:
            _ticket_system_api = importlib.import_module('ticket_system_api')
        except Exception:
            _ticket_system_api = None

        if _ticket_system_api is not None and hasattr(_ticket_system_api, 'create_ticket'):
            ticket_data = {
                'subject': f"Payment Issue: {issue_type} - {payment.id}",
                'description': description,
                'payment_id': payment.id,
                'customer_email': getattr(payment, 'usuario').email if getattr(payment, 'usuario', None) else None,
                'amount': payment.amount,
                'priority': 'high' if payment.amount > 1000 else 'medium'
            }
            ticket_id = _ticket_system_api.create_ticket(ticket_data)
        else:
            # Email fallback to support address
            support_email = getattr(settings, 'SUPPORT_EMAIL', None) or getattr(settings, 'DEFAULT_FROM_EMAIL', None)
            if support_email:
                send_mail(f"[Support] Payment Issue {payment.id}", description, None, [support_email])
                ticket_id = f'email-{payment.id}'

        if ticket_id:
            payment.support_ticket_id = str(ticket_id)
            payment.save(update_fields=['support_ticket_id'])
            return ticket_id
    except Exception:
        logging.exception('create_support_ticket_for_payment_issue failed')
    return None


# --- Multi-currency helpers ---
import decimal
import requests
from django.utils import timezone


def get_current_exchange_rate(source_currency, target_currency='USD'):
    """Obtener tasa de cambio usando exchangerate.host como fallback.
    Retorna un Decimal.
    """
    source = (source_currency or 'USD').upper()
    target = (target_currency or 'USD').upper()
    # Allow overriding via settings for tests or fixed rates
    override = getattr(settings, 'EXCHANGE_RATES_OVERRIDE', None)
    if override and override.get(f"{source}_{target}"):
        return decimal.Decimal(str(override.get(f"{source}_{target}")))
    try:
        resp = requests.get(f'https://api.exchangerate.host/convert?from={source}&to={target}&amount=1')
        if resp.status_code == 200:
            data = resp.json()
            rate = decimal.Decimal(str(data.get('info', {}).get('rate', 1)))
            return rate
    except Exception:
        logging.exception('get_current_exchange_rate failed, falling back to 1')
    return decimal.Decimal('1')


def handle_multi_currency_payment(amount, source_currency, target_currency='USD', payment_instance=None):
    """Convert amount (in cents) from source_currency to target_currency and persist a CurrencyConversion record if payment_instance provided."""
    rate = get_current_exchange_rate(source_currency, target_currency)
    # amount is in cents (int). Convert using rate, keep integer cents
    converted = int(decimal.Decimal(int(amount)) * rate)
    # persist
    try:
        if payment_instance is not None:
            from .models import CurrencyConversion
            conv = CurrencyConversion.objects.create(
                payment=payment_instance,
                original_amount=int(amount),
                original_currency=source_currency,
                converted_amount=int(converted),
                target_currency=target_currency,
                exchange_rate=rate,
            )
            return {
                'original_amount': int(amount),
                'original_currency': source_currency,
                'converted_amount': int(converted),
                'target_currency': target_currency,
                'exchange_rate': rate,
                'conversion_timestamp': conv.conversion_timestamp,
            }
    except Exception:
        logging.exception('handle_multi_currency_payment persistence failed')
    return {
        'original_amount': int(amount),
        'original_currency': source_currency,
        'converted_amount': int(converted),
        'target_currency': target_currency,
        'exchange_rate': rate,
        'conversion_timestamp': timezone.now(),
    }


# --- Payment processor routing helpers ---
def get_processor_success_rates(last_hours=24):
    """Return a dict of processor->success_rate (0..1). This is a stub backed by cache.
    Real implementation would query metrics backend.
    """
    try:
        rates = cache.get('processor_success_rates')
        if rates:
            return rates
    except Exception:
        pass
    # default stub
    default = {
        'processor_a': 0.98,
        'processor_b': 0.95,
        'processor_c': 0.90,
    }
    try:
        cache.set('processor_success_rates', default, 300)
    except Exception:
        pass
    return default


def select_optimal_payment_processor(payment_data):
    HIGH_VALUE_THRESHOLD = getattr(settings, 'HIGH_VALUE_THRESHOLD', 1000 * 100)  # cents
    HIGH_RISK_COUNTRIES = getattr(settings, 'HIGH_RISK_COUNTRIES', [])
    amount = payment_data.get('amount', 0)
    country = payment_data.get('country')
    if amount and int(amount) > HIGH_VALUE_THRESHOLD:
        return 'processor_a'
    if country and country in HIGH_RISK_COUNTRIES:
        return 'processor_c'
    rates = get_processor_success_rates()
    return max(rates, key=rates.get)


# --- Address validation (optional external service) ---
def validate_billing_address(address_data):
    """Validate billing address using optional configured service in settings.
    If no service configured, assume valid and return normalized data.
    """
    service = getattr(settings, 'ADDRESS_VALIDATION_SERVICE', None)
    if service and hasattr(service, 'verify'):
        res = service.verify(address_data)
        if res.get('is_valid'):
            return res.get('normalized_address')
        raise ValueError(res.get('error_message', 'Invalid address'))
    # fallback: basic normalization
    normalized = {
        'line1': address_data.get('line1', '').strip(),
        'line2': address_data.get('line2', '').strip(),
        'city': address_data.get('city', '').strip(),
        'state': address_data.get('state', '').strip(),
        'postal_code': address_data.get('postal_code', '').strip(),
        'country': address_data.get('country', '').upper().strip() if address_data.get('country') else '',
    }
    return normalized


# --- Card lifecycle check ---
def check_expiring_cards():
    """Find cards expiring in the next 30 days and notify owners/administrators.
    This uses Tarjeta.expiry_month/year fields.
    """
    try:
        from django.utils import timezone as _tz
        from datetime import timedelta
        from .models import Tarjeta
        now = _tz.now()
        threshold = now + timedelta(days=30)
        # naive check: loop all cards and compare expiry
        for card in Tarjeta.objects.all():
            if card.expiry_year and card.expiry_month:
                # build a date on the last day of expiry month
                exp_date = _tz.datetime(card.expiry_year, card.expiry_month, 1)
                if exp_date <= threshold:
                    # notify user by email; best-effort
                    try:
                        user = card.cuenta_financiera.usuario
                        send_mail('Tarjeta por expirar', f'Tu tarjeta ****{card.ultimos_digitos} expira pronto.', None, [user.email])
                    except Exception:
                        logging.exception('Failed notifying about expiring card %s', card.id)
    except Exception:
        logging.exception('check_expiring_cards failed')


