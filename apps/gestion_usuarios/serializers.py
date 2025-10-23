from rest_framework import serializers
from django.contrib.auth import get_user_model
from apps.usuarios.models import Role
from apps.usuarios.models import Persona

Usuario = get_user_model()


class UsuarioSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Usuario
        fields = ['id', 'username', 'email', 'rol', 'telefono', 'apartamento', 'activo', 'password']
        read_only_fields = ['id', 'activo']

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        username = validated_data.get('username')
        email = validated_data.get('email')
        # Asegurar existencia de Persona mínima (el modelo Usuario requiere persona)
        persona = validated_data.get('persona')
        if not persona:
            # crear una persona mínima para no romper integridad
            persona = Persona.objects.create(nombre=username or email.split('@')[0], apellido='-', ci=f'autogen-{username or email}', email=email)

        # Use the manager create_user to ensure proper hashing and defaults
        user = Usuario.objects.create_user(username=username, email=email, password=password, persona=persona)
        # set additional optional fields
        for attr in ('rol', 'telefono', 'apartamento'):
            if attr in validated_data:
                setattr(user, attr, validated_data[attr])
        user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class AsignarRolSerializer(serializers.Serializer):
    rol = serializers.ChoiceField(choices=Role.choices)


class CambioPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=False)
    new_password = serializers.CharField()