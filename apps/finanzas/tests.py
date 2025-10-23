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
