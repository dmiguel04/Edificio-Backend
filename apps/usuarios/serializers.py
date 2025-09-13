from rest_framework import serializers
from .models import Persona, Usuario
from .crypto import encrypt_password, decrypt_password  # lo definimos aparte

class PersonaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Persona
        fields = ["nombre", "apellido", "ci", "email", "sexo", "telefono", "fecha_nacimiento"]

class RegisterSerializer(serializers.Serializer):
    persona = PersonaSerializer()
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)

    def create(self, validated_data):
        persona_data = validated_data.pop("persona")
        persona = Persona.objects.create(**persona_data)
        encrypted_password = encrypt_password(validated_data["password"])
        usuario = Usuario.objects.create(
            username=validated_data["username"],
            email=persona.email,
            password_encrypted=encrypted_password,
            persona=persona,
            is_email_verified=True,  # Se marca como verificado automáticamente
        )
        return usuario

    def validate(self, data):
        ci = data['persona']['ci']
        email = data['persona']['email']
        if Persona.objects.filter(ci=ci).exists():
            raise serializers.ValidationError({'ci': 'Ya existe una persona con este CI.'})
        if Persona.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': 'Ya existe una persona con este email.'})
        if Usuario.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError({'username': 'Ya existe un usuario con este username.'})
        return data

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

        # Ya no se valida is_email_verified

        decrypted_pass = decrypt_password(usuario.password_encrypted)
        if decrypted_pass != password:
            raise serializers.ValidationError("Contraseña incorrecta")

        data["usuario"] = usuario
        return data