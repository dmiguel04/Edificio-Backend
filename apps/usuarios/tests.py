from django.test import TestCase
from django.urls import reverse
from apps.usuarios.models import Usuario, Persona


class LoginFlowTests(TestCase):
    def setUp(self):
        persona = Persona.objects.create(nombre='Test', apellido='User', ci='123', email='test@example.com')
        self.user = Usuario.objects.create(username='testuser', email='test@example.com', persona=persona)
        self.user.set_password('pass1234')
        self.user.is_email_verified = True
        self.user.save()

    def test_login_sends_token_and_validate(self):
        url = reverse('login')
        resp = self.client.post(url, {'username': 'testuser', 'password': 'pass1234'}, content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get('require_token') or data.get('requires_token'))

        # Obtain token from DB (OTP)
        u = Usuario.objects.get(username='testuser')
        token = u.login_token
        self.assertIsNotNone(token)

        # Validate token
        url2 = reverse('validate-login-token')
        resp2 = self.client.post(url2, {'username': 'testuser', 'token': token}, content_type='application/json')
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        # access token should be present
        self.assertTrue(data2.get('access') or data2.get('access_token'))

    def test_2fa_flow_requires_2fa(self):
        # enable 2FA pre-setup
        self.user.two_factor_secret = 'JBSWY3DPEHPK3PXP'  # dummy secret
        self.user.two_factor_enabled = True
        self.user.save()

        url = reverse('login')
        resp = self.client.post(url, {'username': 'testuser', 'password': 'pass1234'}, content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get('require_token') or data.get('requires_token'))

        u = Usuario.objects.get(username='testuser')
        token = u.login_token
        url2 = reverse('validate-login-token')
        resp2 = self.client.post(url2, {'username': 'testuser', 'token': token}, content_type='application/json')
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        # should indicate require_2fa
        self.assertTrue(data2.get('require_2fa') or data2.get('requires_2fa') or data2.get('two_factor_enabled'))
from django.test import TestCase

# Create your tests here.
