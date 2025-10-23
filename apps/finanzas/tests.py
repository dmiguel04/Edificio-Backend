import os
import json
from django.test import TestCase, Client
from django.urls import reverse
from django.conf import settings
from unittest import mock

from .models import Payment, WebhookEvent
from django.contrib.auth import get_user_model


class WebhookIdempotencyTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='pass')
        self.client = Client()
        # Create a payment linked to user
        self.payment = Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_test_123', amount=1000, currency='usd', status='pending')

    @mock.patch('apps.finanzas.webhook.import', create=True)
    def test_webhook_processing_and_idempotency(self, mocked_import):
        # We'll patch stripe.Webhook.construct_event by injecting a fake stripe module
        class FakeStripe:
            class error:
                class SignatureVerificationError(Exception):
                    pass

            class Webhook:
                @staticmethod
                def construct_event(payload, sig_header, secret):
                    # return a dict-like event
                    return json.loads(payload)

        # Simulate import stripe returning FakeStripe
        mocked_import.return_value = FakeStripe

        event = {'id': 'evt_1', 'type': 'payment_intent.succeeded', 'data': {'object': {'id': 'pi_test_123'}}}
        payload = json.dumps(event).encode('utf-8')
        # Call webhook first time
        with mock.patch('apps.finanzas.webhook.stripe', FakeStripe):
            response = self.client.post(reverse('stripe-webhook'), data=payload, content_type='application/json', HTTP_STRIPE_SIGNATURE='sig')
        self.assertEqual(response.status_code, 200)

        # Payment should be updated
        p = Payment.objects.get(pk=self.payment.pk)
        self.assertEqual(p.status, 'succeeded')

        # WebhookEvent should be created and marked processed
        we = WebhookEvent.objects.filter(event_id='evt_1').first()
        self.assertIsNotNone(we)
        self.assertTrue(we.processed)

        # Call webhook again with same event id -> should be idempotent (200) and not create duplicate
        with mock.patch('apps.finanzas.webhook.stripe', FakeStripe):
            response2 = self.client.post(reverse('stripe-webhook'), data=payload, content_type='application/json', HTTP_STRIPE_SIGNATURE='sig')
        self.assertEqual(response2.status_code, 200)
        count = WebhookEvent.objects.filter(event_id='evt_1').count()
        self.assertEqual(count, 1)
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from unittest import mock
from rest_framework.test import APIClient

User = get_user_model()


class FinanzasAPITest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='pass1234')
        self.client = APIClient()
        # Force authentication to bypass JWT/session complexity in tests
        self.client.force_authenticate(user=self.user)

    @mock.patch('apps.finanzas.utils.create_stripe_customer')
    def test_create_stripe_customer(self, mock_create_customer):
        mock_create_customer.return_value = {'id': 'cus_test_123'}
        url = reverse('finanzas-create-customer')
        resp = self.client.post(url)
        self.assertEqual(resp.status_code, 201)
        self.assertIn('stripe_customer_id', resp.data or {})

    @mock.patch('apps.finanzas.utils.create_payment_intent')
    def test_create_payment_intent_requires_customer(self, mock_create_intent):
        url = reverse('finanzas-create-payment-intent')
        resp = self.client.post(url, data={'amount': 1000, 'currency': 'usd'})
        # Should fail because stripe customer does not exist yet
        self.assertEqual(resp.status_code, 400)

    def test_payments_list_and_detail(self):
        # Crear un payment local para el usuario
        from .models import Payment
        p = Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_test_1', amount=500, currency='usd', status='succeeded')

        list_url = reverse('finanzas-payments-list')
        resp = self.client.get(list_url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(any(item['stripe_payment_intent'] == 'pi_test_1' for item in resp.json()))

        detail_url = reverse('finanzas-payments-detail', args=[p.id])
        resp2 = self.client.get(detail_url)
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.data['stripe_payment_intent'], 'pi_test_1')

    @mock.patch('apps.finanzas.utils.construct_webhook_event', autospec=True)
    def test_webhook_processes_event(self, mock_construct):
        # Pre-create a Payment with pending status
        from .models import Payment, WebhookEvent
        p = Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_123', amount=100, currency='usd', status='pending')

        # Mock event
        event = {
            'id': 'evt_1',
            'type': 'payment_intent.succeeded',
            'data': {'object': {'id': 'pi_123'}}
        }
        mock_construct.return_value = event

        url = reverse('finanzas-webhook')
        resp = self.client.post(url, data=event, content_type='application/json')
        self.assertEqual(resp.status_code, 200)

        p.refresh_from_db()
        self.assertEqual(p.status, 'succeeded')
        evt = WebhookEvent.objects.get(event_id='evt_1')
        self.assertTrue(evt.processed)

    def test_signed_webhook_verification_and_processing(self):
        """Build a Stripe-compatible signature header and post to the webhook endpoint."""
        import json, time, hmac, hashlib
        from django.conf import settings
        from .models import Payment, WebhookEvent

        # Pre-create a Payment with pending status
        p = Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_signed_123', amount=100, currency='usd', status='pending')

        event = {
            'id': 'evt_signed_1',
            'type': 'payment_intent.succeeded',
            'data': {'object': {'id': 'pi_signed_123'}}
        }
        payload = json.dumps(event)

        # Construct Stripe-like signature header: t=timestamp,v1=HMAC_SHA256(t + '.' + payload)
        timestamp = int(time.time())
        signed_payload = f"{timestamp}.{payload}".encode('utf-8')
        import os
        secret = os.environ.get('STRIPE_WEBHOOK_SECRET') or getattr(settings, 'STRIPE_WEBHOOK_SECRET', '')
        if not secret:
            # If test env has no secret, set a dummy one for the HMAC
            secret = 'whsec_test_secret'
        sig = hmac.new(secret.encode('utf-8'), signed_payload, hashlib.sha256).hexdigest()
        sig_header = f"t={timestamp},v1={sig}"

        url = reverse('finanzas-webhook')
        resp = self.client.post(url, data=payload, content_type='application/json', HTTP_STRIPE_SIGNATURE=sig_header)
        self.assertEqual(resp.status_code, 200)

        p.refresh_from_db()
        self.assertEqual(p.status, 'succeeded')
        evt = WebhookEvent.objects.get(event_id='evt_signed_1')
        self.assertTrue(evt.processed)

    def test_junta_receives_summary(self):
        # crear usuario con rol junta
        from apps.usuarios.models import Usuario
        junta = Usuario.objects.create_user(username='junta1', email='junta@example.com', password='pass1234')
        junta.rol = 'junta'
        junta.save()

        # crear payments
        from .models import Payment
        Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_j1', amount=100, currency='usd', status='succeeded')

        client = APIClient()
        client.force_authenticate(user=junta)
        url = reverse('finanzas-payments-list')
        resp = client.get(url)
        self.assertEqual(resp.status_code, 200)
        # Junta should not receive 'usuario' field
        data = resp.json()
        self.assertTrue(isinstance(data, list))
        self.assertNotIn('usuario', data[0])

    def test_admin_receives_full(self):
        # crear admin
        from apps.usuarios.models import Usuario
        admin = Usuario.objects.create_user(username='admin1', email='admin@example.com', password='pass1234')
        admin.is_staff = True
        admin.save()

        from .models import Payment
        Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_admin1', amount=200, currency='usd', status='succeeded')

        client = APIClient()
        client.force_authenticate(user=admin)
        url = reverse('finanzas-payments-list')
        resp = client.get(url)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('usuario', data[0])

    def test_invoice_pdf_generation_and_storage(self):
        from .models import Invoice
        inv = Invoice.objects.create(usuario=self.user, amount=12345, description='Test invoice')
        url = inv.generate_pdf_qr()
        self.assertTrue(url)

    def test_manual_payment_amount_limit(self):
        # personal attempts to create a payment above limit
        from apps.usuarios.models import Usuario
        personal = Usuario.objects.create_user(username='pers1', email='pers@example.com', password='pass1234')
        personal.rol = 'personal'
        personal.save()

        client = APIClient()
        client.force_authenticate(user=personal)
        url = reverse('finanzas-register-manual')
        large_amount = 9999999999
        resp = client.post(url, data={'usuario_id': self.user.id, 'amount': large_amount})
        self.assertEqual(resp.status_code, 400)

    def test_paymentgateway_admin_only(self):
        from apps.usuarios.models import Usuario
        admin = Usuario.objects.create_user(username='admin2', email='admin2@example.com', password='pass1234')
        admin.is_staff = True
        admin.save()

        client = APIClient()
        client.force_authenticate(user=self.user)  # normal user
        url = reverse('finanzas-gateway')
        resp = client.get(url)
        self.assertEqual(resp.status_code, 403)

        client.force_authenticate(user=admin)
        resp2 = client.get(url)
        self.assertEqual(resp2.status_code, 200)

    def test_create_support_ticket_with_ticket_api(self):
        from .utils import create_support_ticket_for_payment_issue
        from .models import Payment

        # create a payment to attach ticket to
        p = Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_ticket_1', amount=1500, currency='usd', status='pending')

        # mock ticket_system_api.create_ticket
        import importlib, sys
        module_name = 'ticket_system_api'
        fake = type('X', (), {})()
        def fake_create_ticket(data):
            return 'TICKET-123'
        fake.create_ticket = fake_create_ticket
        sys.modules[module_name] = fake

        ticket_id = create_support_ticket_for_payment_issue(p, 'charge_failed', 'Card declined')
        self.assertIsNotNone(ticket_id)
        p.refresh_from_db()
        self.assertEqual(p.support_ticket_id, str(ticket_id))

    def test_create_support_ticket_email_fallback(self):
        from .utils import create_support_ticket_for_payment_issue
        from .models import Payment
        from django.core import mail

        p = Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_ticket_2', amount=500, currency='usd', status='pending')
        # Ensure no ticket_system_api
        import sys
        sys.modules.pop('ticket_system_api', None)

        ticket = create_support_ticket_for_payment_issue(p, 'manual_issue', 'Please check')
        # fallback returns an email-based id
        self.assertIsNotNone(ticket)
        p.refresh_from_db()
        self.assertTrue(p.support_ticket_id.startswith('email-') or p.support_ticket_id is not None)

    def test_log_pii_access_creates_compliancelog(self):
        from .utils import log_pii_access
        from .models import ComplianceLog
        # call logger
        result = log_pii_access(self.user, {'card_last4': '4242'}, 'view_payment', request=None)
        self.assertTrue(result)
        self.assertTrue(ComplianceLog.objects.filter(user=self.user, purpose='view_payment').exists())

    @mock.patch('apps.finanzas.utils.create_checkout_session')
    def test_checkout_session_creation(self, mock_create_session):
        # Mock Stripe checkout session result
        class FakeSession:
            def __init__(self):
                self.url = 'https://checkout.stripe.test/session/abc'
                self.id = 'cs_test_123'

        mock_create_session.return_value = FakeSession()

        url = reverse('finanzas-create-checkout-session')
        payload = {
            'line_items': [
                {
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {'name': 'Test Product'},
                        'unit_amount': 500
                    },
                    'quantity': 1
                }
            ],
            'success_url': 'https://example.com/success',
            'cancel_url': 'https://example.com/cancel'
        }

        resp = self.client.post(url, data=payload, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('url', resp.data)

    @mock.patch('apps.finanzas.utils.create_subscription')
    def test_subscription_creation(self, mock_create_subscription):
        # ensure user has a stripe customer attached
        from .models import StripeCustomer
        StripeCustomer.objects.create(usuario=self.user, stripe_customer_id='cus_test_123')

        class FakeSub:
            def __init__(self):
                self.id = 'sub_test_123'
                self.status = 'active'

        mock_create_subscription.return_value = FakeSub()

        url = reverse('finanzas-subscriptions-create')
        resp = self.client.post(url, data={'price_id': 'price_test_1'}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('id', resp.data)

    def test_invoice_payment_succeeded_webhook_updates_invoice_and_payment(self):
        # Create invoice and associated (simulated) payment record
        from .models import Invoice, Payment, WebhookEvent
        # Create user invoice
        inv = Invoice.objects.create(usuario=self.user, amount=1000, currency='usd', description='Test')
        # Create payment referencing a payment intent id that will appear in invoice.lines.data
        p = Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_invoice_1', amount=1000, currency='usd', status='pending')


        # Build an invoice.payment_succeeded event payload that links to the payment via metadata
        event = {
            'id': 'evt_invoice_paid_1',
            'type': 'invoice.payment_succeeded',
            'data': {
                'object': {
                    'id': f'inv_{inv.id}',
                    'payment_intent': 'pi_invoice_1',
                    'amount_paid': inv.amount,
                    'metadata': {'payment_id': str(p.id)},
                    'lines': {
                        'data': [
                            {'id': 'il_1', 'amount': inv.amount}
                        ]
                    }
                }
            }
        }

        # Post to webhook endpoint using the APIClient (already authenticated) and mock construct_webhook_event
        with mock.patch('apps.finanzas.utils.construct_webhook_event', return_value=event):
            url = reverse('finanzas-webhook')
            resp = self.client.post(url, data=event, content_type='application/json')
            self.assertEqual(resp.status_code, 200)

        # Reload objects
        p.refresh_from_db()
        inv.refresh_from_db()

        # Payment should be marked succeeded and invoice paid True
        self.assertEqual(p.status, 'succeeded')
        self.assertTrue(inv.paid)

    def test_payment_intent_payment_failed_updates_payment(self):
        from .models import Payment
        p = Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_failed_1', amount=1000, currency='usd', status='pending')

        event = {
            'id': 'evt_failed_1',
            'type': 'payment_intent.payment_failed',
            'data': {'object': {'id': 'pi_failed_1', 'last_payment_error': {'message': 'card_declined'}}}
        }

        with mock.patch('apps.finanzas.utils.construct_webhook_event', return_value=event):
            url = reverse('finanzas-webhook')
            resp = self.client.post(url, data=event, content_type='application/json')
            self.assertEqual(resp.status_code, 200)

        p.refresh_from_db()
        self.assertEqual(p.status, 'requires_payment_method')


    def test_payment_intent_canceled_updates_payment(self):
        from .models import Payment
        p = Payment.objects.create(usuario=self.user, stripe_payment_intent='pi_cancel_1', amount=500, currency='usd', status='pending')

        event = {
            'id': 'evt_cancel_1',
            'type': 'payment_intent.canceled',
            'data': {'object': {'id': 'pi_cancel_1'}}
        }

        with mock.patch('apps.finanzas.utils.construct_webhook_event', return_value=event):
            url = reverse('finanzas-webhook')
            resp = self.client.post(url, data=event, content_type='application/json')
            self.assertEqual(resp.status_code, 200)

        p.refresh_from_db()
        self.assertEqual(p.status, 'canceled')

