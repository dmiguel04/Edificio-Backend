from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.contrib.auth.hashers import make_password, check_password
from django.db import models
from apps.usuarios.crypto import encrypt_sensitive_data, decrypt_sensitive_data
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
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=150, unique=True)
    persona = models.OneToOneField(Persona, on_delete=models.CASCADE, related_name="usuario")
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  # hash de contraseña
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    # 🔹 Nuevo campo obligatorio para no romper integridad
    date_joined = models.DateTimeField(default=timezone.now)
    # --- Campos de verificación y seguridad ---
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=64, null=True, blank=True)
    email_verification_expires = models.DateTimeField(null=True, blank=True)
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
        """Hashea la contraseña usando el sistema seguro de Django"""
        self.password = make_password(raw_password)
        self.save()

    def check_password(self, raw_password):
        """Verifica la contraseña usando el sistema de hash de Django"""
        return check_password(raw_password, self.password)

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
        self.huellas_encrypted = encrypt_sensitive_data(b64_str)

    def get_huellas(self) -> bytes:
        if not self.huellas_encrypted:
            return b""
        b64 = decrypt_sensitive_data(self.huellas_encrypted)
        return base64.b64decode(b64)
    # Métodos similares para rostro e iris si los necesitas


class Pago(models.Model):
    id_pago = models.AutoField(primary_key=True)
    metodo_pago = models.CharField(max_length=50)
    fecha_pago = models.DateField(null=True, blank=True)
    estado = models.CharField(max_length=20)
    referencia_bancaria_encrypted = models.TextField(null=True, blank=True)
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE)

    def set_referencia(self, raw_ref: str):
        self.referencia_bancaria_encrypted = encrypt_sensitive_data(raw_ref)

    def get_referencia(self) -> str:
        if not self.referencia_bancaria_encrypted:
            return ""
        return decrypt_sensitive_data(self.referencia_bancaria_encrypted)


class AuditoriaEvento(models.Model):
    EVENTO_CHOICES = [
        ('login_exitoso', 'Login exitoso'),
        ('login_fallido', 'Login fallido'),
        ('logout_exitoso', 'Logout exitoso'),
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
