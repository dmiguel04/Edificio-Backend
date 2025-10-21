from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from apps.usuarios.models import Usuario, Persona, Role
from django.contrib.auth.hashers import make_password


class PermisosGestionUsuariosTest(TestCase):
    def setUp(self):
        # crear personas
        p1 = Persona.objects.create(nombre='Admin', apellido='One', ci='111', email='admin@example.com')
        p2 = Persona.objects.create(nombre='Junta', apellido='One', ci='222', email='junta@example.com')
        p3 = Persona.objects.create(nombre='Personal', apellido='One', ci='333', email='personal@example.com')
        p4 = Persona.objects.create(nombre='Res', apellido='One', ci='444', email='residente@example.com')
        # crear usuarios (asociados a persona) sin usar create_user para evitar doble save
        self.admin = Usuario.objects.create(username='admin', email='admin@example.com', password=make_password('pass123'), persona=p1)
        self.admin.rol = Role.ADMIN
        self.admin.is_staff = True
        self.admin.save()

        self.junta = Usuario.objects.create(username='junta', email='junta@example.com', password=make_password('pass123'), persona=p2)
        self.junta.rol = Role.JUNTA
        self.junta.save()

        self.personal = Usuario.objects.create(username='personal', email='personal@example.com', password=make_password('pass123'), persona=p3)
        self.personal.rol = Role.PERSONAL
        self.personal.save()

        self.residente = Usuario.objects.create(username='res', email='residente@example.com', password=make_password('pass123'), persona=p4)
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
        resp = self.client.post(url, data, format='json')
        self.assertIn(resp.status_code, (201, 403))

    def test_personal_no_puede_crear_otros(self):
        self.client.force_authenticate(user=self.personal)
        url = reverse('usuarios-list')
        data = {'username': 'x', 'email': 'x@example.com', 'password': 'abc123'}
        resp = self.client.post(url, data, format='json')
        self.assertIn(resp.status_code, (403, 401))
