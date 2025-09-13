from django.db import models
from apps.usuarios.crypto import encrypt_password, decrypt_password
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

class Usuario(models.Model):
    id_usuario = models.AutoField(primary_key=True)
    username = models.CharField(max_length=150, unique=True)
    persona = models.OneToOneField(Persona, on_delete=models.CASCADE, related_name="usuario")
    email = models.EmailField(unique=True)
    password_encrypted = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    # --- Nuevos campos para verificación, recuperación y login token ---
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=64, null=True, blank=True)
    reset_password_token = models.CharField(max_length=64, null=True, blank=True)
    login_token = models.CharField(max_length=64, null=True, blank=True)  # <--- Añadido para login por token
    # -------------------------------------------------------------------

    @property
    def id(self):
        return self.id_usuario

    def set_password(self, raw_password):
        self.password_encrypted = encrypt_password(raw_password)

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