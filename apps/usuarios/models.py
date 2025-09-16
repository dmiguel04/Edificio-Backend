from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from apps.usuarios.crypto import encrypt_password, decrypt_password
from django.utils import timezone
import base64

class Persona(models.Model):
    id_persona = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=50)
    apellido = models.CharField(max_length=50)
    ci = models.CharField(max_length=20, unique=True)
    email = models.EmailField(unique=True)
    sexo = models.CharField(max_length=20, null=True, blank=True)
    telefono = models.CharField(max_length=20, null=True, blank=True)
    fecha_nacimiento = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.nombre} {self.apellido}"

class UsuarioManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not username:
            raise ValueError('El usuario debe tener un username')
        if not email:
            raise ValueError('El usuario debe tener un email')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(username, email, password, **extra_fields)

class Usuario(AbstractBaseUser, PermissionsMixin):
    id = models.AutoField(primary_key=True)  # Cambiado de id_usuario a id
    username = models.CharField(max_length=150, unique=True)
    persona = models.OneToOneField(Persona, on_delete=models.CASCADE, related_name="usuario")
    email = models.EmailField(unique=True)
    password_encrypted = models.CharField(max_length=256)
    password = models.CharField(max_length=128, blank=True, default="")
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    # --- Nuevos campos para verificación, recuperación y login token ---
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=64, null=True, blank=True)
    reset_password_token = models.CharField(max_length=64, null=True, blank=True)
    login_token = models.CharField(max_length=64, null=True, blank=True)
    two_factor_secret = models.CharField(max_length=32, null=True, blank=True)
    two_factor_enabled = models.BooleanField(default=False)
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    # -------------------------------------------------------------------

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]

    objects = UsuarioManager()

    def set_password(self, raw_password):
        self.password_encrypted = encrypt_password(raw_password)
        self.password = ""  # No usar el campo password

    def check_password(self, raw_password):
        return decrypt_password(self.password_encrypted) == raw_password

    def __str__(self):
        return self.username

class Biometricos(models.Model):
    id_biometrico = models.AutoField(primary_key=True)
    huellas_encrypted = models.TextField(null=True, blank=True)
    rostro_encrypted = models.TextField(null=True, blank=True)
    iris_encrypted = models.TextField(null=True, blank=True)
    persona = models.ForeignKey(Persona, on_delete=models.CASCADE)

    def set_huellas(self, raw_bytes: bytes):
        b64_str = base64.b64encode(raw_bytes).decode()
        self.huellas_encrypted = encrypt_password(b64_str)

    def get_huellas(self) -> bytes:
        if not self.huellas_encrypted:
            return b""
        b64 = decrypt_password(self.huellas_encrypted)
        return base64.b64decode(b64)

    # Puedes agregar métodos similares para rostro e iris

class Pago(models.Model):
    id_pago = models.AutoField(primary_key=True)
    metodo_pago = models.CharField(max_length=50)
    fecha_pago = models.DateField(null=True, blank=True)
    estado = models.CharField(max_length=20)
    referencia_bancaria_encrypted = models.TextField(null=True, blank=True)
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)

    def set_referencia(self, raw_ref: str):
        self.referencia_bancaria_encrypted = encrypt_password(raw_ref)

    def get_referencia(self) -> str:
        if not self.referencia_bancaria_encrypted:
            return ""
        return decrypt_password(self.referencia_bancaria_encrypted)

class AuditoriaEvento(models.Model):
    EVENTO_CHOICES = [
        ('login_exitoso', 'Login exitoso'),
        ('login_fallido', 'Login fallido'),
        ('cambio_password', 'Cambio de contraseña'),
        ('reset_password', 'Reset de contraseña'),
        ('acceso_no_autorizado', 'Acceso no autorizado'),
    ]
    usuario = models.ForeignKey('Usuario', null=True, blank=True, on_delete=models.SET_NULL)
    username = models.CharField(max_length=150, blank=True)
    evento = models.CharField(max_length=32, choices=EVENTO_CHOICES)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    fecha = models.DateTimeField(default=timezone.now)
    detalle = models.TextField(blank=True)

    def __str__(self):
        return f"{self.evento} - {self.username or self.usuario} - {self.fecha}"