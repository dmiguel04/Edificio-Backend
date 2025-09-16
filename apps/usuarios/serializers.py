from rest_framework import serializers
from .models import Persona, Usuario
from .models import AuditoriaEvento
from .crypto import encrypt_password, decrypt_password
import re
import bleach  # <-- Importa bleach para limpiar HTML

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "abc123", "111111", "123456789", "12345", "123123", "admin"
]

def validar_password(password, nombre='', apellido='', ci='', fecha_nacimiento=''):
    if len(password) < 8:
        raise serializers.ValidationError("La contraseña debe tener al menos 8 caracteres.")
    if not re.search(r"[A-Z]", password):
        raise serializers.ValidationError("La contraseña debe contener al menos una letra mayúscula.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise serializers.ValidationError("La contraseña debe contener al menos un carácter especial.")
    if password.lower() in COMMON_PASSWORDS:
        raise serializers.ValidationError("La contraseña es demasiado común o débil.")
    if (
        nombre and nombre.lower() in password.lower() or
        apellido and apellido.lower() in password.lower() or
        ci and ci in password or
        fecha_nacimiento and str(fecha_nacimiento) in password
    ):
        raise serializers.ValidationError("La contraseña no debe contener tu nombre, apellido, CI o fecha de nacimiento.")

class PersonaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Persona
        fields = ["nombre", "apellido", "ci", "email", "sexo", "telefono", "fecha_nacimiento"]

class RegisterSerializer(serializers.Serializer):
    persona = PersonaSerializer()
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)

    def validate_password(self, value):
        # Validación básica
        if len(value) < 8:
            raise serializers.ValidationError("La contraseña debe tener al menos 8 caracteres.")
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("La contraseña debe contener al menos una letra mayúscula.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise serializers.ValidationError("La contraseña debe contener al menos un carácter especial.")
        if value.lower() in COMMON_PASSWORDS:
            raise serializers.ValidationError("La contraseña es demasiado común o débil.")
        return value

    def validate(self, data):
        ci = data['persona']['ci']
        email = data['persona']['email']
        password = data['password']
        nombre = data['persona']['nombre']
        apellido = data['persona']['apellido']
        fecha_nacimiento = data['persona'].get('fecha_nacimiento', '')

        if Persona.objects.filter(ci=ci).exists():
            raise serializers.ValidationError({'ci': 'Ya existe una persona con este CI.'})
        if Persona.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': 'Ya existe una persona con este email.'})
        if Usuario.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError({'username': 'Ya existe un usuario con este username.'})

        # Prevención de contraseñas que incluyan nombre, apellido, ci o fecha de nacimiento
        if (
            nombre.lower() in password.lower() or
            apellido.lower() in password.lower() or
            ci in password or
            (fecha_nacimiento and str(fecha_nacimiento) in password)
        ):
            raise serializers.ValidationError({'password': 'La contraseña no debe contener tu nombre, apellido, CI o fecha de nacimiento.'})

        return data

    def create(self, validated_data):
        persona_data = validated_data.pop("persona")
        persona = Persona.objects.create(**persona_data)
        encrypted_password = encrypt_password(validated_data["password"])
        usuario = Usuario.objects.create(
            username=validated_data["username"],
            email=persona.email,
            password_encrypted=encrypted_password,
            persona=persona,
            is_email_verified=True,
        )
        return usuario

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")

        try:
            usuario = Usuario.objects.get(username=username)
        except Usuario.DoesNotExist:
            raise serializers.ValidationError("Usuario no encontrado")

        decrypted_pass = decrypt_password(usuario.password_encrypted)
        if decrypted_pass != password:
            raise serializers.ValidationError("Contraseña incorrecta")

        data["usuario"] = usuario
        return data

class AuditoriaEventoSerializer(serializers.ModelSerializer):
    # Ejemplo: Si tienes un campo descripcion que puede contener HTML, límpialo aquí
    def validate_descripcion(self, value):
        return bleach.clean(value)

    class Meta:
        model = AuditoriaEvento
        fields = '__all__'