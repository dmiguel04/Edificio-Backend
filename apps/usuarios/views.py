from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    AuditoriaEventoSerializer,
    validar_password,
)
from .models import Usuario, Persona, AuditoriaEvento
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.permissions import IsAuthenticated, AllowAny
import uuid
from rest_framework import serializers
from django_filters.rest_framework import DjangoFilterBackend
from django.utils import timezone
from datetime import timedelta
import base64

# 2FA / QR
import pyotp
import qrcode
import io
from django.http import HttpResponse

# SQL crudo seguro
from django.db import connection

import logging

logger = logging.getLogger(__name__)

# Alias endpoint helper: allow legacy frontend to POST /api/usuarios/<pk>/assign-role/
from rest_framework.decorators import permission_classes
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated as DRFIsAuthenticated
from apps.gestion_usuarios.permissions import IsAdministrador as IsAdministradorPermission
from apps.gestion_usuarios.serializers import AsignarRolSerializer as GestionAsignarRolSerializer
from apps.usuarios.models import Role as UsuarioRole
from django.shortcuts import get_object_or_404
from django.db import transaction


class MeAPIView(APIView):
    """Retorna los datos del usuario autenticado."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # Devolver un perfil mínimo y el rol para que el frontend pueda usarlo
        data = {
            'id': user.id,
            'username': getattr(user, 'username', None),
            'email': getattr(user, 'email', None),
            'rol': getattr(user, 'rol', None),
            'is_staff': user.is_staff,
        }
        return Response(data)


class UsersRootAPIView(APIView):
    """Simple API root for the usuarios app.

    Returns a JSON object with the main endpoints so GET /api/usuarios/ is not 404.
    This is purely for developer/UX convenience and can be removed later.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        base = request.build_absolute_uri('/api/usuarios/')
        return Response({
            'endpoints': {
                'register': base + 'register/',
                'login': base + 'login/',
                'validate_login_token': base + 'validate-login-token/',
                '2fa_verify': base + '2fa/verify/',
                '2fa_activate': base + '2fa/activate/',
                'forgot_password': base + 'forgot-password/',
                'reset_password': base + 'reset-password/',
                'me': base + 'me/',
            },
            'note': 'This is an index for the usuarios API. Use the specific endpoints for actions.'
        })


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def send_email(subject: str, message: str, recipient_list: list, fail_silently: bool = True):
    """Wrapper around Django send_mail with error logging."""
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list, fail_silently=fail_silently)
    except Exception as e:
        logger.exception("Error sending email to %s: %s", recipient_list, e)

class Activate2FAAPIView(APIView):
    """Genera/retorna el QR/base64 para activar 2FA. Requiere autenticación.

    Retorna JSON con `qr_url` (data URL base64 PNG) para que el frontend lo muestre.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user.two_factor_secret:
            user.two_factor_secret = pyotp.random_base32()
            user.save()

        otp_uri = pyotp.totp.TOTP(user.two_factor_secret).provisioning_uri(
            name=user.email,
            issuer_name="EdificioApp",
        )
        img = qrcode.make(otp_uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        qr_url = f"data:image/png;base64,{img_base64}"
        return Response({"qr_url": qr_url})

class Verify2FAAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        code = request.data.get('code')
        if not username or not code:
            return Response({"error": "Username y código requeridos."}, status=400)
        try:
            user = Usuario.objects.get(username=username)
            if not user.two_factor_secret:
                return Response({"error": "2FA no activado."}, status=400)
            totp = pyotp.TOTP(user.two_factor_secret)
            if totp.verify(code):
                user.two_factor_enabled = True
                user.save()
                # Generar tokens e incluir claim 'role'
                refresh = RefreshToken.for_user(user)
                try:
                    role_val = getattr(user, 'rol', None)
                    if role_val is not None:
                        refresh['role'] = str(role_val)
                        refresh.access_token['role'] = str(role_val)
                except Exception:
                    pass

                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                return Response({
                    "msg": "2FA verificado correctamente.",
                    "message": "2FA verificado correctamente.",
                    "detail": "2FA verificado correctamente.",
                    # principales claves usadas por cliente
                    "access": access_token,
                    "refresh": refresh_token,
                    # variantes esperadas
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                })
            return Response({"error": "Código inválido."}, status=400)
        except Usuario.DoesNotExist:
            return Response({"error": "Usuario no encontrado."}, status=400)


class AssignRoleAliasAPIView(APIView):
    """Alias para mantener compatibilidad con frontend antiguo.

    POST /api/usuarios/<pk>/assign-role/ -> reasigna rol (solo admin)
    """
    permission_classes = [DRFIsAuthenticated, IsAdministradorPermission]

    def post(self, request, pk=None):
        UsuarioModel = Usuario
        usuario = get_object_or_404(UsuarioModel, pk=pk)
        serializer = GestionAsignarRolSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        nuevo_rol = serializer.validated_data['rol']
        if nuevo_rol not in [c[0] for c in UsuarioRole.choices]:
            return Response({'detail': 'Rol inválido'}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            old = usuario.rol
            usuario.rol = nuevo_rol
            usuario.save()
        # Notificar por correo al usuario sobre el cambio de rol (fuera de transacción)
        try:
            subject = 'Cambio de rol - EdificioApp'
            message = f"Hola {usuario.persona.nombre},\n\nTu rol en EdificioApp ha sido actualizado de '{old}' a '{nuevo_rol}'.\n\nSi crees que esto es un error, contacta con el administrador.\n\nSaludos,\nEl equipo de EdificioApp"
            send_email(subject, message, [usuario.email], fail_silently=True)
        except Exception:
            logger.exception('Error enviando correo de notificación de rol a %s', usuario.email)

        return Response({'status': 'rol asignado'})

class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            usuario = serializer.save()

            # Enviar correo de verificación asíncrono (wrapper)
            try:
                send_email(
                    subject="Verifica tu cuenta - EdificioApp",
                    message=f"Tu código de verificación es: {usuario.email_verification_token}",
                    recipient_list=[usuario.email],
                )
            except Exception:
                # No fallamos la creación si el envío de correo falló
                logger.warning("Fallo al enviar correo de verificación para %s", usuario.email)

            return Response(
                {
                    "id_usuario": usuario.id,
                    "username": usuario.username,
                    "email": usuario.email,
                    "message": "¡Registro exitoso! Revisa tu correo para verificar tu cuenta.",
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Eliminada la clase VerifyEmailAPIView

class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        username = request.data.get('username', '')
        ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        usuario = Usuario.objects.filter(username=username).first()
        # Si hay bloqueo temporal y expiró: resetear
        if usuario and usuario.account_locked_until and usuario.account_locked_until <= timezone.now():
            usuario.failed_login_attempts = 0
            usuario.account_locked_until = None
            usuario.save()

        if usuario and usuario.account_locked_until and usuario.account_locked_until > timezone.now():
            return Response({
                "error": "Cuenta bloqueada por demasiados intentos fallidos. Intenta de nuevo en unos minutos."
            }, status=status.HTTP_403_FORBIDDEN)

        if serializer.is_valid():
            usuario = serializer.validated_data["usuario"]
            # Si el usuario debe cambiar la contraseña (creado por admin), bloquear login normal
            if getattr(usuario, 'must_change_password', False):
                return Response({
                    "error": "must_change_password",
                    "message": "Debe establecer una contraseña usando el flujo de restablecimiento.",
                    "msg": "Debe establecer una contraseña usando el flujo de restablecimiento.",
                    "detail": "Debe establecer una contraseña usando el flujo de restablecimiento.",
                }, status=403)

            # Reset counters
            usuario.failed_login_attempts = 0
            usuario.account_locked_until = None
            # Generar OTP de 6 dígitos para flujo de verificación en dos pasos
            import random
            otp = f"{random.randint(0, 999999):06d}"
            usuario.login_token = otp
            usuario.login_token_expires = timezone.now() + timedelta(minutes=10)
            usuario.save()

            # Enviar token por correo (no devolver tokens aquí para forzar validación)
            try:
                send_email(
                    subject="Código de acceso - EdificioApp",
                    message=f"Tu código de acceso temporal es: {otp}\nSi no solicitaste este inicio de sesión, ignora este correo.",
                    recipient_list=[usuario.email],
                )
            except Exception:
                # No exponer fallo de envío al cliente (evitar enumeración)
                logger.exception('Error sending login token to %s', usuario.email)

            # Registrar evento de inicio de login (token enviado)
            AuditoriaEvento.objects.create(
                usuario=usuario,
                username=usuario.username,
                evento='login_iniciado',
                ip=ip,
                user_agent=user_agent,
                detalle='Login iniciado: token enviado por email',
            )

            # Indicar al cliente que debe validar el token recibido.
            # Incluir variantes de claves para que clientes tolerantes manejen distintas respuestas.
            # Incluir 'sent_to' enmascarado para mejor UX inmediato
            sent_to = None
            try:
                e = usuario.email or ''
                if '@' in e:
                    local, domain = e.split('@', 1)
                    if len(local) <= 2:
                        masked_local = local[0] + '*' * (len(local)-1)
                    else:
                        masked_local = local[:2] + '*' * (len(local)-2)
                    sent_to = f"{masked_local}@{domain}"
                else:
                    sent_to = e
            except Exception:
                sent_to = None

            payload = {
                "require_token": True,
                "requires_token": True,
                "token_required": True,
                "message": "Se envió un token a tu correo para continuar con el inicio de sesión.",
                "msg": "Se envió un token a tu correo para continuar con el inicio de sesión.",
                "detail": "Se envió un token a tu correo para continuar con el inicio de sesión.",
                "sent_to": sent_to,
            }

            return Response(payload)

        # Manejo de errores de login: normalizar respuesta JSON
        errors = serializer.errors
        # email_not_verified special case kept
        if usuario and isinstance(errors, dict) and 'email_not_verified' in str(errors):
            AuditoriaEvento.objects.create(
                usuario=usuario,
                username=username,
                evento='login_fallido',
                ip=ip,
                user_agent=user_agent,
                detalle='Login fallido: Email no verificado',
            )
            return Response({
                "error": "email_not_verified",
                "message": "Debes verificar tu correo electrónico antes de iniciar sesión",
                "msg": "Debes verificar tu correo electrónico antes de iniciar sesión",
                "detail": "Debes verificar tu correo electrónico antes de iniciar sesión",
                "email": usuario.email,
            }, status=status.HTTP_400_BAD_REQUEST)

        # contador de intentos fallidos
        if usuario:
            usuario.failed_login_attempts += 1
            if usuario.failed_login_attempts >= 5:
                usuario.account_locked_until = timezone.now() + timedelta(minutes=1)
            usuario.save()

        AuditoriaEvento.objects.create(
            usuario=None,
            username=username,
            evento='login_fallido',
            ip=ip,
            user_agent=user_agent,
            detalle=str(errors),
        )

        # Normalizar errores: si es dict, devolver primer mensaje legible
        message = None
        if isinstance(errors, dict):
            # buscar claves y tomar primer valor
            for k, v in errors.items():
                try:
                    if isinstance(v, (list, tuple)) and v:
                        message = str(v[0])
                    else:
                        message = str(v)
                except Exception:
                    message = str(v)
                break
        else:
            message = str(errors)

        return Response({"error": "invalid_credentials", "message": message, "msg": message, "detail": message}, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            usuario = Usuario.objects.get(email=email)
            token = str(uuid.uuid4())
            usuario.reset_password_token = token
            usuario.save()
            send_email(
                subject="Recupera tu contraseña - EdificioApp",
                message=f"Tu token para restablecer la contraseña es: {token}",
                recipient_list=[usuario.email],
            )
            return Response({"msg": "Correo de recuperación enviado."})
        except Usuario.DoesNotExist:
            return Response({"error": "Email no registrado."}, status=400)

class ResetPasswordAPIView(APIView):
    def post(self, request):
        token = request.data.get('token')
        new_password = request.data.get('new_password')
        if not token or not new_password:
            return Response({"error": "Token y nueva contraseña requeridos."}, status=400)
        try:
            usuario = Usuario.objects.get(reset_password_token=token)
            # validar expiración
            if not usuario.reset_password_expires or usuario.reset_password_expires < timezone.now():
                return Response({"error": "Token expirado."}, status=400)
            persona = usuario.persona
            try:
                validar_password(
                    new_password,
                    nombre=persona.nombre,
                    apellido=persona.apellido,
                    ci=persona.ci,
                    fecha_nacimiento=persona.fecha_nacimiento
                )
            except serializers.ValidationError as e:
                return Response({"error": str(e.detail[0])}, status=400)
            usuario.set_password(new_password)
            # limpiar flags de restablecimiento
            usuario.reset_password_token = None
            usuario.reset_password_expires = None
            usuario.must_change_password = False
            usuario.save()
            ip = request.META.get('REMOTE_ADDR')
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            AuditoriaEvento.objects.create(
                usuario=usuario,
                username=usuario.username,
                evento='reset_password',
                ip=get_client_ip(request),
                user_agent=user_agent,
                detalle='Reset de contraseña exitoso'
            )
            return Response({"msg": "Contraseña restablecida."})
        except Usuario.DoesNotExist:
            ip = request.META.get('REMOTE_ADDR')
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            AuditoriaEvento.objects.create(
                usuario=None,
                username='',
                evento='acceso_no_autorizado',
                ip=ip,
                user_agent=user_agent,
                detalle='Intento de reset con token inválido'
            )
            return Response({"error": "Token inválido."}, status=400)

class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        new_password = request.data.get('new_password')
        if not new_password:
            return Response({"error": "new_password requerido"}, status=400)
        user.set_password(new_password)
        user.save()
        AuditoriaEvento.objects.create(
            usuario=user,
            username=user.username,
            evento='cambio_password',
            ip=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            detalle='Cambio de contraseña exitoso',
        )
        return Response({"msg": "Contraseña cambiada correctamente."})

class ValidateLoginTokenAPIView(APIView):
    def post(self, request):
        # Aceptar variantes de campo para username y token
        username = request.data.get('username') or request.data.get('user') or request.data.get('email')
        token = request.data.get('token') or request.data.get('code') or request.data.get('login_token') or request.data.get('email_token')

        if not username or not token:
            return Response({"error": "username y token requeridos.", "message": "username y token requeridos.", "msg": "username y token requeridos.", "detail": "username y token requeridos."}, status=400)

        try:
            # Buscar por username o email
            try:
                usuario = Usuario.objects.get(username=username)
            except Usuario.DoesNotExist:
                usuario = Usuario.objects.filter(email=username).first()
            if not usuario:
                return Response({"error": "Usuario no encontrado.", "message": "Usuario no encontrado.", "detail": "Usuario no encontrado."}, status=400)

            # Comparar token
            if not usuario.login_token or usuario.login_token != token:
                # Incrementar contador de intentos fallidos para el usuario
                try:
                    usuario.failed_login_attempts = (usuario.failed_login_attempts or 0) + 1
                    if usuario.failed_login_attempts >= 5:
                        usuario.account_locked_until = timezone.now() + timedelta(minutes=1)
                    usuario.save()
                except Exception:
                    pass

                return Response({"error": "Token inválido.", "message": "Token inválido.", "detail": "Token inválido."}, status=400)

            # Token válido: limpiar
            usuario.login_token = None
            usuario.save()

            # Si no tiene 2FA activado, emitir tokens JWT directamente
            if not usuario.two_factor_enabled:
                try:
                    refresh = RefreshToken.for_user(usuario)
                    try:
                        role_val = getattr(usuario, 'rol', None)
                        if role_val is not None:
                            refresh['role'] = str(role_val)
                            refresh.access_token['role'] = str(role_val)
                    except Exception:
                        pass
                    access_token = str(refresh.access_token)
                    refresh_token = str(refresh)

                    AuditoriaEvento.objects.create(
                        usuario=usuario,
                        username=usuario.username,
                        evento='login_exitoso',
                        ip=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        detalle='Login correcto via token',
                    )

                    # Devolver tokens con variantes para clientes tolerantes
                    # Incluir información útil para el cliente: a qué email fue enviado (enmascarado)
                    sent_to = None
                    try:
                        e = usuario.email or ''
                        if '@' in e:
                            local, domain = e.split('@', 1)
                            if len(local) <= 2:
                                masked_local = local[0] + '*' * (len(local)-1)
                            else:
                                masked_local = local[:2] + '*' * (len(local)-2)
                            sent_to = f"{masked_local}@{domain}"
                        else:
                            sent_to = e
                    except Exception:
                        sent_to = None

                    return Response({
                        "access": access_token,
                        "refresh": refresh_token,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "message": "Login correcto.",
                        "msg": "Login correcto.",
                        "detail": "Login correcto.",
                        "sent_to": sent_to,
                    })
                except Exception as e:
                    logger.exception('Error issuing JWT after token validation for %s: %s', usuario.username, e)
                    return Response({"error": "token_issue_failed"}, status=500)

            # Si ya tiene 2FA activado, indicar que se requiere código 2FA
            payload_2fa = {
                "require_2fa": True,
                "requires_2fa": True,
                "two_factor_enabled": True,
                "message": "Se requiere código 2FA para completar el login.",
                "msg": "Se requiere código 2FA para completar el login.",
                "detail": "Se requiere código 2FA para completar el login.",
            }
            return Response(payload_2fa)
        except Usuario.DoesNotExist:
            return Response({"error": "Usuario no encontrado."}, status=400)

class CheckPersonaAPIView(APIView):
    def get(self, request):
        ci = request.query_params.get('ci')
        email = request.query_params.get('email')
        data = {}

        if ci:
            data['ci_exists'] = Persona.objects.filter(ci=ci).exists()
        if email:
            data['email_exists'] = Persona.objects.filter(email=email).exists()
        
        return Response(data, status=status.HTTP_200_OK)

class AuditoriaEventoListAPIView(generics.ListAPIView):
    queryset = AuditoriaEvento.objects.all().order_by('-fecha')
    serializer_class = AuditoriaEventoSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['evento', 'username', 'fecha']
    
class LogoutAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Logout optimizado para frontend con timeouts
        - Respuesta rápida (< 200ms)
        - Siempre retorna 200 OK para evitar errores en frontend
        - Blacklist de tokens en background si es posible
        """
        refresh_token = request.data.get("refresh")
        access_token = request.data.get("access")
        
        # Respuesta inmediata al frontend
        response_data = {
            "msg": "Logout exitoso",
            "status": "success", 
            "timestamp": timezone.now().isoformat(),
            "next_action": "redirect_to_login"
        }
        
        # Intentar blacklist en background (no bloquear respuesta)
        try:
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                
            # Registrar evento de logout en auditoría
            user = getattr(request, 'user', None)
            if user and hasattr(user, 'username'):
                AuditoriaEvento.objects.create(
                    usuario=user if user.is_authenticated else None,
                    username=user.username if user.is_authenticated else 'anonymous',
                    evento='logout_exitoso',
                    ip=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    detalle='Logout manual exitoso'
                )
        except Exception as e:
            # Log error pero no fallar el logout
            print(f"Warning: Error en blacklist durante logout: {e}")
            
        # SIEMPRE retornar 200 OK para que frontend pueda limpiar tokens
        return Response(response_data, status=200)
    
    def get_client_ip(self, request):
        """Obtener IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class LogoutAllSessionsAPIView(APIView):
    """Logout masivo - Cerrar todas las sesiones del usuario"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Cierra todas las sesiones activas del usuario
        - Útil al cambiar contraseña
        - Útil cuando hay actividad sospechosa
        """
        user = request.user
        
        try:
            # Obtener todos los refresh tokens del usuario y blacklistearlos
            from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
            
            outstanding_tokens = OutstandingToken.objects.filter(user=user)
            blacklisted_count = 0
            
            for token in outstanding_tokens:
                try:
                    refresh_token = RefreshToken(token.token)
                    refresh_token.blacklist()
                    blacklisted_count += 1
                except Exception:
                    continue  # Token ya blacklisted o inválido
            
            # Registrar evento de logout masivo
            AuditoriaEvento.objects.create(
                usuario=user,
                username=user.username,
                evento='logout_exitoso',
                ip=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                detalle=f'Logout masivo - {blacklisted_count} sesiones cerradas'
            )
            
            return Response({
                "msg": "Todas las sesiones han sido cerradas exitosamente",
                "sessions_closed": blacklisted_count,
                "status": "success",
                "next_action": "redirect_to_login"
            }, status=200)
            
        except Exception as e:
            return Response({
                "msg": "Logout masivo completado (con advertencias)",
                "status": "partial_success", 
                "warning": "Algunas sesiones podrían seguir activas",
                "next_action": "redirect_to_login"
            }, status=200)  # Siempre 200 para no romper frontend
    
    def get_client_ip(self, request):
        """Obtener IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

# --- Ejemplo de consulta SQL cruda protegida ---
class UsuarioRawAPIView(APIView):
    def get(self, request):
        username = request.query_params.get('username')
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM usuarios_usuario WHERE username = %s", [username])
            row = cursor.fetchone()
            columns = [col[0] for col in cursor.description]
        if row:
            usuario_dict = dict(zip(columns, row))
            return Response({"usuario": usuario_dict})
        else:
            return Response({"error": "Usuario no encontrado"}, status=404)
# --- Comentario sobre biometría ---
# Para implementar biometría como segundo factor:
# 1. El usuario registra sus datos biométricos (huella, rostro, etc.) en el sistema.
# 2. Al iniciar sesión, el frontend solicita la biometría al usuario (usando WebAuthn, sensores del dispositivo, etc.).
# 3. El frontend envía la información biométrica al backend.
# 4. El backend valida la biometría contra los datos almacenados y, si es correcta, permite el acceso.
# Nota: La implementación depende del hardware y del soporte del navegador/dispositivo.

class AccountStatusAPIView(APIView):
    def get(self, request):
        username = request.query_params.get('username')
        if not username:
            return Response({"error": "Username requerido"}, status=400)
        try:
            usuario = Usuario.objects.get(username=username)
            # Convertir a hora local si existe bloqueo
            account_locked_until = usuario.account_locked_until
            if account_locked_until:
                account_locked_until = timezone.localtime(account_locked_until)
                account_locked_until = account_locked_until.strftime('%Y-%m-%d %H:%M:%S')
            return Response({
                "account_locked_until": account_locked_until,
                "failed_login_attempts": usuario.failed_login_attempts
            })
        except Usuario.DoesNotExist:
            return Response({"error": "Usuario no encontrado"}, status=404)


# ===== NUEVAS VISTAS PARA VERIFICACIÓN DE EMAIL =====

class VerificarEmailAPIView(APIView):
    """Verificar email con código de verificación"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        codigo = request.data.get('codigo')
        
        if not email:
            return Response({"error": "Email requerido"}, status=400)
        if not codigo:
            return Response({"error": "Código de verificación requerido"}, status=400)
        
        try:
            usuario = Usuario.objects.get(email=email, email_verification_token=codigo)
            
            # Verificar si el código ha expirado
            if usuario.email_verification_expires and timezone.now() > usuario.email_verification_expires:
                return Response({
                    "error": "Código expirado", 
                    "message": "El código de verificación ha expirado. Solicita un nuevo correo de verificación."
                }, status=400)
            
            # Verificar email
            usuario.is_email_verified = True
            usuario.email_verification_token = None
            usuario.email_verification_expires = None
            usuario.save()
            
            return Response({
                "message": "¡Email verificado exitosamente!",
                "verified": True,
                "username": usuario.username,
                "email": usuario.email,
                "redirect": "/login",
                "next_step": "Ahora puedes iniciar sesión con normalidad",
                "login_endpoint": "/api/usuarios/login/"
            }, status=200)
            
        except Usuario.DoesNotExist:
            return Response({"error": "Email o código inválido"}, status=400)


class ReenviarVerificacionAPIView(APIView):
    """Reenviar correo de verificación si el token expiró"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email requerido"}, status=400)
        
        try:
            usuario = Usuario.objects.get(email=email)
            
            # Verificar si ya está verificado
            if usuario.is_email_verified:
                return Response({"message": "El email ya está verificado. Puedes iniciar sesión."}, status=200)
            
            # Generar nuevo código de verificación y nueva fecha de expiración  
            import random
            usuario.email_verification_token = str(random.randint(100000, 999999))
            usuario.email_verification_expires = timezone.now() + timedelta(hours=24)
            usuario.save()
            
            # Enviar nuevo correo
            self._send_verification_email(usuario)
            
            return Response({
                "message": "Correo de verificación reenviado exitosamente",
                "expires_in": "24 horas"
            }, status=200)
            
        except Usuario.DoesNotExist:
            return Response({"error": "No existe un usuario con ese email"}, status=404)
    
    def _send_verification_email(self, usuario):
        """Envía correo de verificación al usuario"""
        subject = "Nuevo código de verificación - EdificioApp"
        
        message = f"""
        ¡Hola {usuario.persona.nombre}!
        
        Has solicitado un nuevo código de verificación para tu cuenta en EdificioApp.
        
        Para completar tu registro, por favor ingresa el siguiente código de verificación en la aplicación:
        
        CÓDIGO DE VERIFICACIÓN: {usuario.email_verification_token}
        
        Este código expirará en 24 horas.
        
        Si no solicitaste esto, puedes ignorar este correo.
        
        Saludos,
        El equipo de EdificioApp
        """
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [usuario.email],
                fail_silently=False,
            )
        except Exception as e:
            print(f"Error enviando correo de verificación: {e}")
            pass