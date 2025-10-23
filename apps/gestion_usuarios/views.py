from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .serializers import UsuarioSerializer, AsignarRolSerializer, CambioPasswordSerializer
from .permissions import IsAdministrador, AdminOrSelf
from rest_framework.permissions import IsAuthenticated
from django.db import transaction
from django.utils.translation import gettext as _
import logging
from apps.usuarios.models import Role
from django.core.mail import send_mail
from django.conf import settings
import secrets
from django.utils import timezone
from datetime import timedelta


Usuario = get_user_model()


class UsuarioViewSet(viewsets.ModelViewSet):
    queryset = Usuario.objects.all()
    serializer_class = UsuarioSerializer
    permission_classes = [IsAuthenticated]

    logger = logging.getLogger(__name__)

    def _parse_bool(self, value):
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).lower() in ('1', 'true', 't', 'yes', 'y')

    def get_permissions(self):
        # permisos por acción
        if self.action in ['create', 'destroy', 'assign_role', 'set_active']:
            # create/destroy/assign_role/set_active: por defecto solo admin
            return [IsAuthenticated(), IsAdministrador()]
        if self.action in ['partial_update', 'update']:
            # permitir admin o el propio usuario
            return [IsAuthenticated(), AdminOrSelf()]
        return [IsAuthenticated()]

    def create(self, request, *args, **kwargs):
        # admin puede crear cualquier usuario. Junta puede crear Personal o Residente.
        user = request.user
        data = request.data.copy()
        rol_solicitado = data.get('rol')

        # Validación temprana de rol solicitado
        if rol_solicitado and rol_solicitado not in [c[0] for c in Role.choices]:
            return Response({'detail': _('Rol inválido')}, status=status.HTTP_400_BAD_REQUEST)

        requester_role = getattr(user, 'rol', None)
        # Admin: puede crear cualquier usuario
        if requester_role == Role.ADMIN:
            # Generar token de restablecimiento y crear usuario con password temporal interno
            reset_token = secrets.token_urlsafe(24)
            internal_password = secrets.token_urlsafe(12)
            data = data.copy()
            data['password'] = internal_password

            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            with transaction.atomic():
                usuario = serializer.save()
                # Guardar token de restablecimiento en el usuario
                usuario.reset_password_token = reset_token
                # Expiración del token: 24 horas
                usuario.reset_password_expires = timezone.now() + timedelta(hours=24)
                usuario.must_change_password = True
                # Marcar contraseña como unusable para forzar uso del flujo de restablecimiento
                try:
                    usuario.set_unusable_password()
                except Exception:
                    # si el modelo no implementa set_unusable_password por alguna razón,
                    # mantenemos la contraseña interna (menos ideal)
                    pass
                usuario.save()
                self.logger.info("Usuario %s crea nuevo usuario (admin): %s", user.username, usuario.username)

            # Enviar correo con enlace de restablecimiento (fuera de la transacción)
            try:
                subject = 'Cuenta creada - Configura tu contraseña en EdificioApp'
                reset_link = f"https://tu-frontend.example.com/reset-password?token={reset_token}&u={usuario.username}"
                message = (
                    f"Hola {usuario.persona.nombre},\n\n"
                    f"Se ha creado una cuenta para ti en EdificioApp con el usuario: {usuario.username}.\n\n"
                    f"Para configurar tu contraseña por favor usa el siguiente enlace (expira en 24 horas):\n{reset_link}\n\n"
                    "Si no solicitaste esto, contacta con el administrador.\n\nSaludos,\nEl equipo de EdificioApp"
                )
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [usuario.email], fail_silently=False)
                self.logger.info("Correo de configuración enviado a %s", usuario.email)
            except Exception as e:
                self.logger.exception("Error enviando correo de bienvenida a %s: %s", usuario.email, e)

            return Response(self.get_serializer(usuario).data, status=status.HTTP_201_CREATED)

        # Junta: sólo puede crear personal o residente (o por defecto residente)
        if requester_role == Role.JUNTA:
            allowed = {Role.PERSONAL, Role.RESIDENTE}
            # si no se especifica, se permite (serializer aplicará default)
            if not rol_solicitado or rol_solicitado in allowed:
                with transaction.atomic():
                    self.logger.info("Usuario %s crea nuevo usuario (junta)", user.username)
                    return super().create(request, *args, **kwargs)
            return Response({'detail': _('Junta no puede asignar ese rol.')}, status=status.HTTP_403_FORBIDDEN)

        # resto de roles no pueden crear usuarios
        return Response({'detail': _('No autorizado')}, status=status.HTTP_403_FORBIDDEN)

    @action(detail=True, methods=['post'], url_path='assign-role', permission_classes=[IsAuthenticated, IsAdministrador])
    def assign_role(self, request, pk=None):
        """Asignar rol a un usuario (solo admin)."""
        usuario = get_object_or_404(Usuario, pk=pk)
        serializer = AsignarRolSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        nuevo_rol = serializer.validated_data['rol']
        if nuevo_rol not in [c[0] for c in Role.choices]:
            return Response({'detail': _('Rol inválido')}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            old = usuario.rol
            usuario.rol = nuevo_rol
            usuario.save()
            self.logger.info("Usuario %s cambió rol de %s -> %s", request.user.username, old, nuevo_rol)

        # Notificar por correo al usuario sobre el cambio de rol (fuera de transacción)
        try:
            subject = 'Cambio de rol - EdificioApp'
            message = f"Hola {usuario.persona.nombre},\n\nTu rol en EdificioApp ha sido actualizado de '{old}' a '{nuevo_rol}'.\n\nSi crees que esto es un error, contacta con el administrador.\n\nSaludos,\nEl equipo de EdificioApp"
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [usuario.email], fail_silently=False)
            self.logger.info("Correo de notificación de rol enviado a %s", usuario.email)
        except Exception as e:
            self.logger.exception("Error enviando correo de notificación de rol a %s: %s", usuario.email, e)

        return Response({'status': 'rol asignado'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='set-active', permission_classes=[IsAuthenticated, IsAdministrador])
    def set_active(self, request, pk=None):
        usuario = get_object_or_404(Usuario, pk=pk)
        activo = request.data.get('activo')
        activo_bool = self._parse_bool(activo)
        with transaction.atomic():
            if activo_bool:
                usuario.activar()
                action = 'activado'
            else:
                usuario.desactivar()
                action = 'desactivado'
            self.logger.info("Usuario %s %s al usuario %s", request.user.username, action, usuario.username)
        return Response({'status': 'ok', 'action': action}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], url_path='change-password', permission_classes=[IsAuthenticated])
    def change_password(self, request):
        """Cambiar contraseña: propio usuario. Admin puede forzar si pasa 'username' en payload."""
        serializer = CambioPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_password = serializer.validated_data['new_password']

        target_username = request.data.get('username')
        # Si viene username y el requester es admin, cambiar la contraseña de ese usuario
        if target_username and getattr(request.user, 'rol', None) == Role.ADMIN:
            target = get_object_or_404(Usuario, username=target_username)
            with transaction.atomic():
                target.set_password(new_password)
                target.save()
                self.logger.info("Admin %s forzó cambio de password para %s", request.user.username, target.username)
            return Response({'status': 'password cambiado (admin)'}, status=status.HTTP_200_OK)

        # Si no es admin o no proporcionó username, cambiar la propia contraseña
        user = request.user
        if getattr(request.user, 'rol', None) != Role.ADMIN:
            old = serializer.validated_data.get('old_password')
            if not old or not user.check_password(old):
                return Response({'detail': _('old password incorrecto')}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            user.set_password(new_password)
            user.save()
            self.logger.info("Usuario %s cambió su contraseña", user.username)
        return Response({'status': 'password cambiado'}, status=status.HTTP_200_OK)