import stripe
from django.conf import settings


def get_stripe_api_key():
    return getattr(settings, 'STRIPE_SECRET_KEY', None)


def create_stripe_customer(email, name):
    stripe.api_key = get_stripe_api_key()
    return stripe.Customer.create(email=email, name=name)


def create_payment_intent(amount, currency, customer_id):
    stripe.api_key = get_stripe_api_key()
    return stripe.PaymentIntent.create(
        amount=amount,
        currency=currency,
        customer=customer_id,
        automatic_payment_methods={'enabled': True},
    )


def construct_webhook_event(payload, sig_header, webhook_secret):
    stripe.api_key = get_stripe_api_key()
    if webhook_secret:
        return stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    return stripe.Event.construct_from(payload, stripe.api_key)
