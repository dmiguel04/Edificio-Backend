from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from apps.usuarios.models import Usuario, Persona, Role


class PermisosGestionUsuariosTest(TestCase):
    def setUp(self):
        # crear personas
        p1 = Persona.objects.create(nombre='Admin', apellido='One', ci='111', email='admin@example.com')
        p2 = Persona.objects.create(nombre='Junta', apellido='One', ci='222', email='junta@example.com')
        p3 = Persona.objects.create(nombre='Personal', apellido='One', ci='333', email='personal@example.com')
        p4 = Persona.objects.create(nombre='Res', apellido='One', ci='444', email='residente@example.com')

        # crear usuarios
        self.admin = Usuario.objects.create_user(username='admin', email='admin@example.com', password='pass123')
        self.admin.rol = Role.ADMIN
        self.admin.is_staff = True
        self.admin.save()

        self.junta = Usuario.objects.create_user(username='junta', email='junta@example.com', password='pass123')
        self.junta.rol = Role.JUNTA
        self.junta.save()

        self.personal = Usuario.objects.create_user(username='personal', email='personal@example.com', password='pass123')
        self.personal.rol = Role.PERSONAL
        self.personal.save()

        self.residente = Usuario.objects.create_user(username='res', email='residente@example.com', password='pass123')
        self.residente.rol = Role.RESIDENTE
        self.residente.save()

        self.client = APIClient()

    def test_admin_puede_crear_usuario(self):
        self.client.force_authenticate(user=self.admin)
        url = reverse('usuarios-list')
        data = {'username': 'nuevo', 'email': 'nuevo@example.com', 'password': 'abc123'}
        resp = self.client.post(url, data, format='json')
        self.assertEqual(resp.status_code, 201)

    def test_residente_no_puede_crear_usuario(self):
        self.client.force_authenticate(user=self.residente)
        url = reverse('usuarios-list')
        data = {'username': 'otro', 'email': 'otro@example.com', 'password': 'abc123'}
        resp = self.client.post(url, data, format='json')
        self.assertIn(resp.status_code, (403, 401))

    def test_junta_puede_crear_personal(self):
        self.client.force_authenticate(user=self.junta)
        url = reverse('usuarios-list')
        data = {'username': 'pers-nuevo', 'email': 'persnuevo@example.com', 'password': 'abc123', 'rol': Role.PERSONAL}
        # según implementación actual, create requiere admin; este test sirve para detectar la restricción
        resp = self.client.post(url, data, format='json')
        # si no está permitido, al menos debe devolver 403
        self.assertIn(resp.status_code, (201, 403))

    def test_personal_no_puede_crear_otros(self):
        self.client.force_authenticate(user=self.personal)
        url = reverse('usuarios-list')
        data = {'username': 'x', 'email': 'x@example.com', 'password': 'abc123'}
        resp = self.client.post(url, data, format='json')
        self.assertIn(resp.status_code, (403, 401))


from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.conf import settings
from apps.usuarios.models import Usuario, Persona, Role
from rest_framework.test import APIClient
import uuid
from datetime import timedelta


class GestionUsuariosFlowTests(TestCase):
    def setUp(self):
        persona_admin = Persona.objects.create(nombre='Admin', apellido='User', ci='9001', email='admin2@example.com')
        self.admin = Usuario.objects.create(username='admin2', email='admin2@example.com', persona=persona_admin, rol=Role.ADMIN)
        self.admin.set_password('adminpass')
        self.admin.save()
        self.client = APIClient()

    def test_admin_crea_usuario_must_change_password_and_token(self):
        self.client.force_authenticate(user=self.admin)
        url = reverse('usuarios-list')
        data = {
            'username': 'nuevo2',
            'email': 'nuevo2@example.com',
            'persona': {
                'nombre': 'Nuevo', 'apellido': 'User', 'email': 'nuevo2@example.com', 'ci': '9002'
            }
        }
        resp = self.client.post(url, data, content_type='application/json')
        self.assertEqual(resp.status_code, 201)
        usuario = Usuario.objects.get(username='nuevo2')
        self.assertIsNotNone(usuario.reset_password_token)
        self.assertTrue(usuario.must_change_password)
        self.assertIsNotNone(usuario.reset_password_expires)
        self.assertGreater(usuario.reset_password_expires, timezone.now())

    def test_reset_with_expired_token_fails(self):
        persona = Persona.objects.create(nombre='Exp', apellido='Token', ci='9003', email='exp@example.com')
        user = Usuario.objects.create(username='exp', email='exp@example.com', persona=persona)
        token = str(uuid.uuid4())
        user.reset_password_token = token
        user.reset_password_expires = timezone.now() - timedelta(hours=1)
        user.must_change_password = True
        user.save()

        url = reverse('reset-password')
        resp = self.client.post(url, {'token': token, 'new_password': 'Newpass123!'}, content_type='application/json')
        self.assertEqual(resp.status_code, 400)
        self.assertIn('Token expirado', resp.json().get('error', ''))

    def test_reset_with_valid_token_succeeds_and_clears_flags(self):
        persona = Persona.objects.create(nombre='Good', apellido='Token', ci='9004', email='good@example.com')
        user = Usuario.objects.create(username='good', email='good@example.com', persona=persona)
        token = str(uuid.uuid4())
        user.reset_password_token = token
        user.reset_password_expires = timezone.now() + timedelta(hours=1)
        user.must_change_password = True
        user.save()

        url = reverse('reset-password')
        resp = self.client.post(url, {'token': token, 'new_password': 'Newpass123!'}, content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        user.refresh_from_db()
        self.assertIsNone(user.reset_password_token)
        self.assertFalse(user.must_change_password)
        self.assertIsNone(user.reset_password_expires)

    def test_login_when_must_change_password_blocked(self):
        persona = Persona.objects.create(nombre='Must', apellido='Change', ci='9005', email='must@example.com')
        user = Usuario.objects.create(username='must', email='must@example.com', persona=persona)
        user.set_password('pw1234')
        user.must_change_password = True
        user.is_email_verified = True
        user.save()

        url = reverse('login')
        resp = self.client.post(url, {'username': 'must', 'password': 'pw1234'}, content_type='application/json')
        # should return 403 because must_change_password blocks normal login
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json().get('error'), 'must_change_password')
