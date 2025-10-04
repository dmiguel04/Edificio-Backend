# ============================================================================
# IMPORTS - Organizados por categorías para mejor mantenibilidad
# ============================================================================

# Python standard library
import base64
import io
import logging
import random
import uuid
from datetime import timedelta
from typing import Dict, Any, Optional

# Django core
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.db import connection, transaction
from django.http import HttpResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_headers

# Django REST Framework
from rest_framework import generics, status, serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

# Third party packages
from django_filters.rest_framework import DjangoFilterBackend
import pyotp
import qrcode

# Local imports
from .models import Usuario, Persona, AuditoriaEvento
from .serializers import RegisterSerializer, LoginSerializer, AuditoriaEventoSerializer, validar_password

# ============================================================================
# CONFIGURACIÓN DE LOGGING
# ============================================================================
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTES Y CONFIGURACIONES
# ============================================================================
class SecurityConfig:
    """Configuraciones de seguridad centralizadas"""
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=15)  # Incrementado para mayor seguridad
    EMAIL_VERIFICATION_EXPIRY = timedelta(hours=24)
    PASSWORD_RESET_EXPIRY = timedelta(hours=1)
    LOGIN_TOKEN_EXPIRY = timedelta(minutes=15)

class Messages:
    """Mensajes de respuesta centralizados"""
    LOGIN_SUCCESS = "Inicio de sesión exitoso"
    LOGOUT_SUCCESS = "Sesión cerrada exitosamente"
    REGISTRATION_SUCCESS = "Registro completado. Verifica tu correo electrónico"
    EMAIL_VERIFIED = "Email verificado exitosamente"
    PASSWORD_RESET_SUCCESS = "Contraseña restablecida correctamente"
    ACCOUNT_LOCKED = "Cuenta temporalmente bloqueada por múltiples intentos fallidos"
    INVALID_CREDENTIALS = "Credenciales inválidas"
    EMAIL_NOT_VERIFIED = "Debes verificar tu correo electrónico antes de continuar"

# ============================================================================
# UTILIDADES COMUNES
# ============================================================================

class SecurityUtils:
    """Utilidades de seguridad reutilizables"""
    
    @staticmethod
    def get_client_ip(request) -> str:
        """Obtener la IP real del cliente considerando proxies"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Tomar la primera IP de la cadena (IP original del cliente)
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip
    
    @staticmethod
    def get_user_agent(request) -> str:
        """Obtener el user agent del cliente"""
        return request.META.get('HTTP_USER_AGENT', 'unknown')
    
    @staticmethod
    def create_audit_event(usuario, username: str, evento: str, request, detalle: str = ''):
        """Crear evento de auditoría de forma consistente"""
        try:
            AuditoriaEvento.objects.create(
                usuario=usuario,
                username=username,
                evento=evento,
                ip=SecurityUtils.get_client_ip(request),
                user_agent=SecurityUtils.get_user_agent(request),
                detalle=detalle
            )
        except Exception as e:
            logger.error(f"Error creando evento de auditoría: {e}")
    
    @staticmethod
    def handle_failed_login(usuario: Usuario, request) -> bool:
        """
        Manejar intento de login fallido
        Returns: True si la cuenta fue bloqueada, False en caso contrario
        """
        if not usuario:
            return False
            
        usuario.failed_login_attempts += 1
        account_locked = False
        
        if usuario.failed_login_attempts >= SecurityConfig.MAX_LOGIN_ATTEMPTS:
            usuario.account_locked_until = timezone.now() + SecurityConfig.ACCOUNT_LOCKOUT_DURATION
            account_locked = True
            logger.warning(f"Cuenta bloqueada por múltiples intentos: {usuario.username}")
        
        usuario.save()
        return account_locked
    
    @staticmethod
    def check_account_lockout(usuario: Usuario) -> bool:
        """
        Verificar y limpiar bloqueo de cuenta si ya expiró
        Returns: True si la cuenta está bloqueada, False en caso contrario
        """
        if not usuario.account_locked_until:
            return False
            
        if usuario.account_locked_until <= timezone.now():
            # El bloqueo ya expiró, limpiar
            usuario.failed_login_attempts = 0
            usuario.account_locked_until = None
            usuario.save()
            return False
        
        return True

class EmailUtils:
    """Utilidades para manejo de correos electrónicos"""
    
    @staticmethod
    def send_verification_email(usuario: Usuario) -> bool:
        """Enviar correo de verificación de email"""
        try:
            # Generar código de verificación
            if not usuario.email_verification_token:
                usuario.email_verification_token = str(random.randint(100000, 999999))
                usuario.email_verification_expires = timezone.now() + SecurityConfig.EMAIL_VERIFICATION_EXPIRY
                usuario.save()
            
            subject = "Verificación de cuenta - EdificioApp"
            message = f"""
            ¡Hola {usuario.persona.nombre}!
            
            Gracias por registrarte en EdificioApp.
            
            Para completar tu registro, por favor verifica tu correo electrónico usando el siguiente código:
            
            CÓDIGO DE VERIFICACIÓN: {usuario.email_verification_token}
            
            Este código expirará en 24 horas.
            
            Si no te registraste en nuestra plataforma, puedes ignorar este correo.
            
            Saludos,
            El equipo de EdificioApp
            """
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [usuario.email],
                fail_silently=False,
            )
            
            logger.info(f"Correo de verificación enviado a: {usuario.email}")
            return True
            
        except Exception as e:
            logger.error(f"Error enviando correo de verificación a {usuario.email}: {e}")
            return False
    
    @staticmethod
    def send_login_token(usuario: Usuario) -> bool:
        """Enviar token de login por correo"""
        try:
            login_token = str(uuid.uuid4())
            usuario.login_token = login_token
            usuario.save()
            
            subject = "Token de acceso - EdificioApp"
            message = f"""
            Hola {usuario.persona.nombre},
            
            Has solicitado iniciar sesión en EdificioApp.
            
            Tu token de acceso es: {login_token}
            
            Este token expirará en 15 minutos por seguridad.
            
            Si no fuiste tú quien solicitó este acceso, ignora este correo y considera cambiar tu contraseña.
            
            Saludos,
            El equipo de EdificioApp
            """
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [usuario.email],
                fail_silently=False,
            )
            
            logger.info(f"Token de login enviado a: {usuario.email}")
            return True
            
        except Exception as e:
            logger.error(f"Error enviando token de login a {usuario.email}: {e}")
            return False

class TwoFactorUtils:
    """Utilidades para autenticación de dos factores"""
    
    @staticmethod
    def generate_qr_code(usuario: Usuario) -> str:
        """Generar código QR para 2FA"""
        try:
            if not usuario.two_factor_secret:
                secret = pyotp.random_base32()
                usuario.two_factor_secret = secret
                usuario.save()
            else:
                secret = usuario.two_factor_secret
            
            otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=usuario.email,
                issuer_name="EdificioApp"
            )
            
            img = qrcode.make(otp_uri)
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            
            return f"data:image/png;base64,{img_base64}"
            
        except Exception as e:
            logger.error(f"Error generando código QR para {usuario.username}: {e}")
            return ""
    
    @staticmethod
    def verify_2fa_code(usuario: Usuario, code: str) -> bool:
        """Verificar código 2FA"""
        try:
            if not usuario.two_factor_secret or not code:
                return False
            
            totp = pyotp.TOTP(usuario.two_factor_secret)
            return totp.verify(code)
            
        except Exception as e:
            logger.error(f"Error verificando código 2FA para {usuario.username}: {e}")
            return False

# ============================================================================
# VISTAS DE API - Organizadas por funcionalidad
# ============================================================================

class Activate2FAAPIView(APIView):
    """
    API para activar autenticación de dos factores (2FA)
    Genera y retorna un código QR para configurar 2FA en apps como Google Authenticator
    """
    permission_classes = [IsAuthenticated]  # Cambiado a IsAuthenticated por seguridad

    def get(self, request):
        """Generar código QR para configuración de 2FA"""
        try:
            user = request.user
            
            # Verificar que el usuario tenga una persona asociada
            if not hasattr(user, 'persona'):
                return Response(
                    {"error": "Usuario sin información de persona asociada"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Generar QR usando la utilidad
            qr_data_url = TwoFactorUtils.generate_qr_code(user)
            
            if not qr_data_url:
                return Response(
                    {"error": "Error generando código QR"}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Crear evento de auditoría
            SecurityUtils.create_audit_event(
                usuario=user,
                username=user.username,
                evento='login_exitoso',  # Usar evento existente o crear uno nuevo
                request=request,
                detalle='Generación de código QR para 2FA'
            )
            
            return Response({
                "qr_code": qr_data_url,
                "message": "Escanea este código QR con tu app de autenticación",
                "instructions": [
                    "1. Abre tu app de autenticación (Google Authenticator, Authy, etc.)",
                    "2. Escanea el código QR mostrado",
                    "3. Ingresa el código de 6 dígitos para activar 2FA"
                ]
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error en Activate2FAAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class Verify2FAAPIView(APIView):
    """
    API para verificar código 2FA y completar la autenticación
    Activa 2FA para el usuario y genera tokens JWT
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Verificar código 2FA y activar la funcionalidad"""
        try:
            # Validar datos de entrada
            username = request.data.get('username', '').strip()
            code = request.data.get('code', '').strip()
            
            if not username:
                return Response(
                    {"error": "Username es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not code:
                return Response(
                    {"error": "Código de verificación es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Buscar usuario con optimización
            try:
                user = Usuario.objects.select_related('persona').get(username=username)
            except Usuario.DoesNotExist:
                # Crear evento de auditoría para intento con usuario inexistente
                SecurityUtils.create_audit_event(
                    usuario=None,
                    username=username,
                    evento='acceso_no_autorizado',
                    request=request,
                    detalle='Intento de verificación 2FA con usuario inexistente'
                )
                return Response(
                    {"error": "Usuario no encontrado"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Verificar que el usuario tenga 2FA configurado
            if not user.two_factor_secret:
                return Response(
                    {"error": "2FA no está configurado para este usuario"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verificar el código 2FA
            if TwoFactorUtils.verify_2fa_code(user, code):
                # Activar 2FA y resetear intentos fallidos
                with transaction.atomic():
                    user.two_factor_enabled = True
                    user.failed_login_attempts = 0
                    user.account_locked_until = None
                    user.save()
                
                # Generar tokens JWT
                refresh = RefreshToken.for_user(user)
                
                # Crear evento de auditoría exitoso
                SecurityUtils.create_audit_event(
                    usuario=user,
                    username=user.username,
                    evento='login_exitoso',
                    request=request,
                    detalle='2FA verificado correctamente - Login completado'
                )
                
                return Response({
                    "message": "2FA verificado correctamente",
                    "user_info": {
                        "username": user.username,
                        "email": user.email,
                        "nombre_completo": f"{user.persona.nombre} {user.persona.apellido}"
                    },
                    "tokens": {
                        "access": str(refresh.access_token),
                        "refresh": str(refresh)
                    },
                    "two_factor_enabled": True
                }, status=status.HTTP_200_OK)
            
            else:
                # Código inválido - manejar como intento fallido
                SecurityUtils.handle_failed_login(user, request)
                
                # Crear evento de auditoría
                SecurityUtils.create_audit_event(
                    usuario=user,
                    username=user.username,
                    evento='login_fallido',
                    request=request,
                    detalle='Código 2FA inválido'
                )
                
                return Response(
                    {"error": "Código de verificación inválido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            logger.error(f"Error en Verify2FAAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class RegisterAPIView(APIView):
    """
    API para registro de nuevos usuarios
    Crea usuario y persona, envía correo de verificación
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Registrar un nuevo usuario en el sistema"""
        try:
            # Validar datos con el serializer
            serializer = RegisterSerializer(data=request.data)
            
            if not serializer.is_valid():
                # Log de intento de registro fallido
                logger.warning(f"Intento de registro fallido desde IP {SecurityUtils.get_client_ip(request)}: {serializer.errors}")
                return Response(
                    {
                        "error": "Datos de registro inválidos",
                        "details": serializer.errors
                    }, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Crear usuario dentro de una transacción
            with transaction.atomic():
                usuario = serializer.save()
                
                # Enviar correo de verificación
                email_sent = EmailUtils.send_verification_email(usuario)
                
                if not email_sent:
                    logger.warning(f"No se pudo enviar correo de verificación a: {usuario.email}")
                
            # Crear evento de auditoría
            SecurityUtils.create_audit_event(
                usuario=usuario,
                username=usuario.username,
                evento='login_exitoso',  # Usar evento existente o crear uno nuevo para registro
                request=request,
                detalle='Registro de usuario exitoso'
            )
            
            # Log de registro exitoso
            logger.info(f"Usuario registrado exitosamente: {usuario.username}")
            
            # Respuesta de éxito
            return Response({
                "success": True,
                "message": Messages.REGISTRATION_SUCCESS,
                "user_info": {
                    "id": usuario.id,
                    "username": usuario.username,
                    "email": usuario.email,
                    "nombre_completo": f"{usuario.persona.nombre} {usuario.persona.apellido}"
                },
                "next_steps": {
                    "action": "verify_email",
                    "description": "Revisa tu bandeja de entrada y verifica tu correo electrónico",
                    "email_sent_to": usuario.email,
                    "expires_in": "24 horas",
                    "verification_endpoint": "/api/usuarios/verificar-email/",
                    "resend_endpoint": "/api/usuarios/reenviar-verificacion/"
                },
                "email_sent": email_sent
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error en RegisterAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor durante el registro"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LoginAPIView(APIView):
    """
    API para inicio de sesión con múltiples capas de seguridad
    Incluye: verificación de email, bloqueo por intentos fallidos, token por correo
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Procesar intento de inicio de sesión"""
        try:
            # Extraer y validar datos básicos
            username = request.data.get('username', '').strip()
            
            if not username:
                return Response(
                    {"error": "Username es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Buscar usuario con optimización
            usuario = Usuario.objects.select_related('persona').filter(username=username).first()
            
            # Verificar bloqueo de cuenta (si existe el usuario)
            if usuario and SecurityUtils.check_account_lockout(usuario):
                # Calcular tiempo restante de bloqueo
                tiempo_restante = usuario.account_locked_until - timezone.now()
                minutos_restantes = int(tiempo_restante.total_seconds() / 60)
                
                SecurityUtils.create_audit_event(
                    usuario=usuario,
                    username=username,
                    evento='acceso_no_autorizado',
                    request=request,
                    detalle=f'Intento de login con cuenta bloqueada - {minutos_restantes} minutos restantes'
                )
                
                return Response({
                    "error": Messages.ACCOUNT_LOCKED,
                    "details": f"Intenta nuevamente en {minutos_restantes} minutos",
                    "locked_until": usuario.account_locked_until.isoformat(),
                    "reason": "Múltiples intentos de login fallidos"
                }, status=status.HTTP_423_LOCKED)
            
            # Validar credenciales con serializer
            serializer = LoginSerializer(data=request.data)
            
            if serializer.is_valid():
                # Login exitoso - procesar
                usuario = serializer.validated_data["usuario"]
                
                with transaction.atomic():
                    # Resetear intentos fallidos
                    usuario.failed_login_attempts = 0
                    usuario.account_locked_until = None
                    
                    # Enviar token de login
                    token_sent = EmailUtils.send_login_token(usuario)
                    
                    if not token_sent:
                        logger.error(f"No se pudo enviar token de login a: {usuario.email}")
                        return Response(
                            {"error": "Error enviando token de acceso"}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                
                # Crear evento de auditoría exitoso
                SecurityUtils.create_audit_event(
                    usuario=usuario,
                    username=usuario.username,
                    evento='login_exitoso',
                    request=request,
                    detalle='Credenciales válidas - Token de acceso enviado'
                )
                
                logger.info(f"Login exitoso para usuario: {username}")
                
                return Response({
                    "success": True,
                    "message": "Credenciales verificadas correctamente",
                    "next_step": {
                        "action": "verify_login_token",
                        "description": "Se ha enviado un token de acceso a tu correo electrónico",
                        "email_sent_to": usuario.email,
                        "expires_in": "15 minutos",
                        "endpoint": "/api/usuarios/validar-token-login/"
                    },
                    "user_info": {
                        "username": usuario.username,
                        "email": usuario.email
                    }
                }, status=status.HTTP_200_OK)
            
            else:
                # Manejar errores específicos del serializer
                return self._handle_login_errors(serializer.errors, username, usuario, request)
                
        except Exception as e:
            logger.error(f"Error en LoginAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _handle_login_errors(self, errors: dict, username: str, usuario: Usuario, request) -> Response:
        """Manejar diferentes tipos de errores de login"""
        
        # Verificar si es error de email no verificado
        if isinstance(errors, dict) and 'email_not_verified' in str(errors):
            SecurityUtils.create_audit_event(
                usuario=usuario,
                username=username,
                evento='login_fallido',
                request=request,
                detalle='Login fallido: Email no verificado'
            )
            
            return Response({
                "error": "email_not_verified",
                "message": Messages.EMAIL_NOT_VERIFIED,
                "details": {
                    "email": usuario.email if usuario else None,
                    "verification_endpoint": "/api/usuarios/verificar-email/",
                    "resend_endpoint": "/api/usuarios/reenviar-verificacion/"
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Para otros errores (credenciales inválidas, etc.)
        if usuario:
            account_locked = SecurityUtils.handle_failed_login(usuario, request)
            
            if account_locked:
                SecurityUtils.create_audit_event(
                    usuario=usuario,
                    username=username,
                    evento='acceso_no_autorizado',
                    request=request,
                    detalle=f'Cuenta bloqueada tras {SecurityConfig.MAX_LOGIN_ATTEMPTS} intentos fallidos'
                )
                
                return Response({
                    "error": Messages.ACCOUNT_LOCKED,
                    "details": f"Has superado el límite de {SecurityConfig.MAX_LOGIN_ATTEMPTS} intentos",
                    "locked_duration": f"{SecurityConfig.ACCOUNT_LOCKOUT_DURATION.total_seconds()/60:.0f} minutos"
                }, status=status.HTTP_423_LOCKED)
        
        # Error genérico de credenciales
        SecurityUtils.create_audit_event(
            usuario=None,
            username=username,
            evento='login_fallido',
            request=request,
            detalle=f'Credenciales inválidas: {str(errors)}'
        )
        
        return Response({
            "error": Messages.INVALID_CREDENTIALS,
            "details": errors
        }, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordAPIView(APIView):
    """
    API para solicitar recuperación de contraseña
    Envía token de recuperación por correo electrónico
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Solicitar token de recuperación de contraseña"""
        try:
            email = request.data.get('email', '').strip().lower()
            
            if not email:
                return Response(
                    {"error": "Email es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validar formato de email básico
            if '@' not in email or '.' not in email:
                return Response(
                    {"error": "Formato de email inválido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                # Buscar usuario con optimización
                usuario = Usuario.objects.select_related('persona').get(email=email)
                
                # Generar token de recuperación
                with transaction.atomic():
                    token = str(uuid.uuid4())
                    usuario.reset_password_token = token
                    # Agregar expiración del token
                    usuario.save()
                
                # Enviar correo de recuperación
                try:
                    subject = "Recuperación de contraseña - EdificioApp"
                    message = f"""
                    Hola {usuario.persona.nombre},
                    
                    Has solicitado restablecer tu contraseña en EdificioApp.
                    
                    Tu token de recuperación es: {token}
                    
                    Este token expirará en 1 hora por seguridad.
                    
                    Si no solicitaste este cambio, ignora este correo y considera cambiar tu contraseña.
                    
                    Saludos,
                    El equipo de EdificioApp
                    """
                    
                    send_mail(
                        subject,
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        [usuario.email],
                        fail_silently=False,
                    )
                    
                    # Crear evento de auditoría
                    SecurityUtils.create_audit_event(
                        usuario=usuario,
                        username=usuario.username,
                        evento='reset_password',
                        request=request,
                        detalle='Solicitud de recuperación de contraseña - Token enviado'
                    )
                    
                    logger.info(f"Token de recuperación enviado a: {email}")
                    
                    return Response({
                        "success": True,
                        "message": "Si el email existe en nuestro sistema, recibirás un correo con instrucciones",
                        "next_steps": {
                            "action": "check_email",
                            "description": "Revisa tu bandeja de entrada y utiliza el token para restablecer tu contraseña",
                            "expires_in": "1 hora",
                            "reset_endpoint": "/api/usuarios/reset-password/"
                        }
                    }, status=status.HTTP_200_OK)
                    
                except Exception as e:
                    logger.error(f"Error enviando correo de recuperación a {email}: {e}")
                    return Response(
                        {"error": "Error enviando correo de recuperación"}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
                    
            except Usuario.DoesNotExist:
                # Por seguridad, no revelar que el email no existe
                # Simular respuesta exitosa para evitar enumeración de usuarios
                SecurityUtils.create_audit_event(
                    usuario=None,
                    username='',
                    evento='acceso_no_autorizado',
                    request=request,
                    detalle=f'Solicitud de recuperación con email inexistente: {email}'
                )
                
                # Esperar un poco para simular procesamiento
                import time
                time.sleep(1)
                
                return Response({
                    "success": True,
                    "message": "Si el email existe en nuestro sistema, recibirás un correo con instrucciones",
                    "next_steps": {
                        "action": "check_email",
                        "description": "Revisa tu bandeja de entrada y utiliza el token para restablecer tu contraseña",
                        "expires_in": "1 hora",
                        "reset_endpoint": "/api/usuarios/reset-password/"
                    }
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            logger.error(f"Error en ForgotPasswordAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ResetPasswordAPIView(APIView):
    """
    API para restablecer contraseña usando token de recuperación
    Incluye validación de seguridad de contraseña
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Restablecer contraseña con token de recuperación"""
        try:
            # Validar datos de entrada
            token = request.data.get('token', '').strip()
            new_password = request.data.get('new_password', '')
            
            if not token:
                return Response(
                    {"error": "Token de recuperación es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not new_password:
                return Response(
                    {"error": "Nueva contraseña es requerida"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                # Buscar usuario por token con optimización
                usuario = Usuario.objects.select_related('persona').get(reset_password_token=token)
                
                # Validar fortaleza de la contraseña
                try:
                    persona = usuario.persona
                    validar_password(
                        new_password,
                        nombre=persona.nombre,
                        apellido=persona.apellido,
                        ci=persona.ci,
                        fecha_nacimiento=persona.fecha_nacimiento
                    )
                except serializers.ValidationError as e:
                    return Response({
                        "error": "La contraseña no cumple con los requisitos de seguridad",
                        "details": str(e.detail[0]) if e.detail else "Contraseña débil"
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Restablecer contraseña dentro de transacción
                with transaction.atomic():
                    usuario.set_password(new_password)
                    usuario.reset_password_token = None  # Limpiar token usado
                    # Resetear intentos fallidos por seguridad
                    usuario.failed_login_attempts = 0
                    usuario.account_locked_until = None
                    usuario.save()
                
                # Crear evento de auditoría
                SecurityUtils.create_audit_event(
                    usuario=usuario,
                    username=usuario.username,
                    evento='reset_password',
                    request=request,
                    detalle='Contraseña restablecida exitosamente'
                )
                
                logger.info(f"Contraseña restablecida para usuario: {usuario.username}")
                
                # Notificar por correo (opcional - para seguridad)
                try:
                    send_mail(
                        "Contraseña restablecida - EdificioApp",
                        f"""
                        Hola {usuario.persona.nombre},
                        
                        Tu contraseña ha sido restablecida exitosamente.
                        
                        Si no fuiste tú quien realizó este cambio, contacta inmediatamente con soporte.
                        
                        Saludos,
                        El equipo de EdificioApp
                        """,
                        settings.DEFAULT_FROM_EMAIL,
                        [usuario.email],
                        fail_silently=True,
                    )
                except Exception as e:
                    logger.error(f"Error enviando notificación de contraseña restablecida: {e}")
                
                return Response({
                    "success": True,
                    "message": Messages.PASSWORD_RESET_SUCCESS,
                    "next_steps": {
                        "action": "login",
                        "description": "Ahora puedes iniciar sesión con tu nueva contraseña",
                        "login_endpoint": "/api/usuarios/login/"
                    }
                }, status=status.HTTP_200_OK)
                
            except Usuario.DoesNotExist:
                # Token inválido o expirado
                SecurityUtils.create_audit_event(
                    usuario=None,
                    username='',
                    evento='acceso_no_autorizado',
                    request=request,
                    detalle=f'Intento de reset con token inválido: {token[:10]}...'
                )
                
                return Response({
                    "error": "Token de recuperación inválido o expirado",
                    "details": "Solicita un nuevo token de recuperación",
                    "forgot_password_endpoint": "/api/usuarios/forgot-password/"
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error en ResetPasswordAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ChangePasswordAPIView(APIView):
    """
    API para cambio de contraseña por usuario autenticado
    Requiere contraseña actual y nueva contraseña
    """
    permission_classes = [IsAuthenticated]  # Corregido: debe ser IsAuthenticated

    def post(self, request):
        """Cambiar contraseña del usuario autenticado"""
        try:
            user = request.user
            current_password = request.data.get('current_password', '')
            new_password = request.data.get('new_password', '')
            
            # Validar datos de entrada
            if not current_password:
                return Response(
                    {"error": "Contraseña actual es requerida"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not new_password:
                return Response(
                    {"error": "Nueva contraseña es requerida"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verificar contraseña actual
            if not user.check_password(current_password):
                SecurityUtils.create_audit_event(
                    usuario=user,
                    username=user.username,
                    evento='acceso_no_autorizado',
                    request=request,
                    detalle='Intento de cambio de contraseña con contraseña actual incorrecta'
                )
                return Response(
                    {"error": "Contraseña actual incorrecta"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validar que la nueva contraseña sea diferente
            if current_password == new_password:
                return Response(
                    {"error": "La nueva contraseña debe ser diferente a la actual"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validar fortaleza de la nueva contraseña
            try:
                persona = user.persona
                validar_password(
                    new_password,
                    nombre=persona.nombre,
                    apellido=persona.apellido,
                    ci=persona.ci,
                    fecha_nacimiento=persona.fecha_nacimiento
                )
            except serializers.ValidationError as e:
                return Response({
                    "error": "La nueva contraseña no cumple con los requisitos de seguridad",
                    "details": str(e.detail[0]) if e.detail else "Contraseña débil"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Cambiar contraseña dentro de transacción
            with transaction.atomic():
                user.set_password(new_password)
                # Resetear intentos fallidos por seguridad
                user.failed_login_attempts = 0
                user.account_locked_until = None
                user.save()
            
            # Crear evento de auditoría
            SecurityUtils.create_audit_event(
                usuario=user,
                username=user.username,
                evento='cambio_password',
                request=request,
                detalle='Cambio de contraseña exitoso por usuario autenticado'
            )
            
            logger.info(f"Contraseña cambiada por usuario: {user.username}")
            
            # Notificar por correo
            try:
                send_mail(
                    "Contraseña actualizada - EdificioApp",
                    f"""
                    Hola {user.persona.nombre},
                    
                    Tu contraseña ha sido actualizada exitosamente.
                    
                    Si no fuiste tú quien realizó este cambio, contacta inmediatamente con soporte.
                    
                    Por seguridad, te recomendamos cerrar todas las sesiones activas.
                    
                    Saludos,
                    El equipo de EdificioApp
                    """,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=True,
                )
            except Exception as e:
                logger.error(f"Error enviando notificación de cambio de contraseña: {e}")
            
            return Response({
                "success": True,
                "message": "Contraseña actualizada correctamente",
                "recommendations": [
                    "Cierra todas las sesiones activas por seguridad",
                    "Actualiza la contraseña en todos tus dispositivos"
                ],
                "logout_all_endpoint": "/api/usuarios/logout-all/"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error en ChangePasswordAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ValidateLoginTokenAPIView(APIView):
    """
    API para validar token de login y proceder con 2FA
    Segundo paso del proceso de autenticación
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """Validar token de login y configurar 2FA si es necesario"""
        try:
            # Validar datos de entrada
            username = request.data.get('username', '').strip()
            token = request.data.get('token', '').strip()
            
            if not username:
                return Response(
                    {"error": "Username es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not token:
                return Response(
                    {"error": "Token de login es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                # Buscar usuario con optimización
                usuario = Usuario.objects.select_related('persona').get(username=username)
                
                # Validar token
                if not usuario.login_token or usuario.login_token != token:
                    SecurityUtils.create_audit_event(
                        usuario=usuario,
                        username=username,
                        evento='acceso_no_autorizado',
                        request=request,
                        detalle='Token de login inválido'
                    )
                    return Response(
                        {"error": "Token de login inválido o expirado"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Token válido - limpiar token usado
                with transaction.atomic():
                    usuario.login_token = None
                    usuario.save()
                
                # Verificar estado de 2FA
                if not usuario.two_factor_enabled:
                    # Primera vez - generar QR para configurar 2FA
                    qr_url = TwoFactorUtils.generate_qr_code(usuario)
                    
                    if not qr_url:
                        return Response(
                            {"error": "Error configurando 2FA"}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                    
                    SecurityUtils.create_audit_event(
                        usuario=usuario,
                        username=usuario.username,
                        evento='login_exitoso',
                        request=request,
                        detalle='Token validado - Configuración inicial de 2FA'
                    )
                    
                    return Response({
                        "step": "setup_2fa",
                        "message": "Configura la autenticación de dos factores",
                        "qr_code": qr_url,
                        "instructions": [
                            "1. Descarga una app de autenticación (Google Authenticator, Authy, etc.)",
                            "2. Escanea el código QR con la app",
                            "3. Ingresa el código de 6 dígitos que aparece en la app"
                        ],
                        "next_endpoint": "/api/usuarios/verify-2fa/",
                        "user_info": {
                            "username": usuario.username,
                            "email": usuario.email
                        }
                    }, status=status.HTTP_200_OK)
                
                else:
                    # 2FA ya configurado - solicitar código
                    SecurityUtils.create_audit_event(
                        usuario=usuario,
                        username=usuario.username,
                        evento='login_exitoso',
                        request=request,
                        detalle='Token validado - Solicitando código 2FA'
                    )
                    
                    return Response({
                        "step": "verify_2fa",
                        "message": "Ingresa tu código de autenticación de dos factores",
                        "require_2fa": True,
                        "next_endpoint": "/api/usuarios/verify-2fa/",
                        "user_info": {
                            "username": usuario.username,
                            "email": usuario.email
                        }
                    }, status=status.HTTP_200_OK)
                    
            except Usuario.DoesNotExist:
                SecurityUtils.create_audit_event(
                    usuario=None,
                    username=username,
                    evento='acceso_no_autorizado',
                    request=request,
                    detalle='Validación de token con usuario inexistente'
                )
                return Response(
                    {"error": "Usuario no encontrado"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
                
        except Exception as e:
            logger.error(f"Error en ValidateLoginTokenAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CheckPersonaAPIView(APIView):
    """
    API para verificar disponibilidad de CI y email
    Útil para validación en tiempo real durante el registro
    """
    permission_classes = [AllowAny]
    
    @method_decorator(cache_page(60))  # Cache por 1 minuto
    def get(self, request):
        """Verificar disponibilidad de CI y/o email"""
        try:
            ci = request.query_params.get('ci', '').strip()
            email = request.query_params.get('email', '').strip().lower()
            
            if not ci and not email:
                return Response(
                    {"error": "Se requiere al menos CI o email para verificar"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            data = {}
            
            # Verificar CI si se proporciona
            if ci:
                if len(ci) < 5:  # Validación básica de CI
                    data['ci_valid'] = False
                    data['ci_error'] = "CI debe tener al menos 5 caracteres"
                else:
                    data['ci_exists'] = Persona.objects.filter(ci=ci).exists()
                    data['ci_valid'] = True
            
            # Verificar email si se proporciona
            if email:
                if '@' not in email or '.' not in email:  # Validación básica
                    data['email_valid'] = False
                    data['email_error'] = "Formato de email inválido"
                else:
                    data['email_exists'] = Persona.objects.filter(email=email).exists()
                    data['email_valid'] = True
            
            # Agregar recomendaciones
            recommendations = []
            if data.get('ci_exists'):
                recommendations.append("El CI ya está registrado en el sistema")
            if data.get('email_exists'):
                recommendations.append("El email ya está registrado en el sistema")
            
            if recommendations:
                data['recommendations'] = recommendations
            
            return Response(data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error en CheckPersonaAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class AuditoriaEventoListAPIView(generics.ListAPIView):
    """
    API para listar eventos de auditoría del sistema
    Incluye filtros avanzados y paginación optimizada
    """
    serializer_class = AuditoriaEventoSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['evento', 'username', 'fecha']
    permission_classes = [IsAuthenticated]  # Solo usuarios autenticados
    
    def get_queryset(self):
        """Optimizar queryset con select_related para mejor rendimiento"""
        return AuditoriaEvento.objects.select_related('usuario').order_by('-fecha')
    
    @method_decorator(vary_on_headers('Authorization'))
    def list(self, request, *args, **kwargs):
        """Listar eventos con metadata adicional"""
        try:
            # Verificar permisos adicionales (solo staff puede ver auditoría completa)
            user = request.user
            if not user.is_staff:
                # Usuarios normales solo pueden ver sus propios eventos
                self.queryset = self.get_queryset().filter(usuario=user)
            
            response = super().list(request, *args, **kwargs)
            
            # Agregar metadata útil
            if hasattr(response, 'data') and isinstance(response.data, dict):
                # Agregar estadísticas si es staff
                if user.is_staff:
                    total_eventos = AuditoriaEvento.objects.count()
                    eventos_hoy = AuditoriaEvento.objects.filter(
                        fecha__date=timezone.now().date()
                    ).count()
                    
                    response.data['metadata'] = {
                        'total_events': total_eventos,
                        'events_today': eventos_hoy,
                        'user_permissions': 'staff',
                        'filters_available': ['evento', 'username', 'fecha']
                    }
                else:
                    response.data['metadata'] = {
                        'user_permissions': 'limited',
                        'note': 'Solo puedes ver tus propios eventos'
                    }
            
            return response
            
        except Exception as e:
            logger.error(f"Error en AuditoriaEventoListAPIView: {e}")
            return Response(
                {"error": "Error obteniendo eventos de auditoría"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
class LogoutAPIView(APIView):
    """
    API para logout seguro y optimizado
    - Respuesta rápida para frontend
    - Blacklist de tokens JWT
    - Auditoría de eventos
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Cerrar sesión del usuario actual
        Optimizado para timeouts de frontend con respuesta rápida
        """
        try:
            refresh_token = request.data.get("refresh", "").strip()
            user = getattr(request, 'user', None)
            
            # Preparar respuesta inmediata
            response_data = {
                "success": True,
                "message": Messages.LOGOUT_SUCCESS,
                "timestamp": timezone.now().isoformat(),
                "next_action": "redirect_to_login"
            }
            
            # Procesar blacklist de token de forma segura
            token_blacklisted = False
            if refresh_token:
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                    token_blacklisted = True
                    logger.info(f"Token blacklisted durante logout")
                except Exception as e:
                    logger.warning(f"Error en blacklist durante logout: {e}")
                    # No fallar el logout por problemas de blacklist
            
            # Crear evento de auditoría (no bloquear respuesta)
            try:
                if user and user.is_authenticated:
                    SecurityUtils.create_audit_event(
                        usuario=user,
                        username=user.username,
                        evento='logout_exitoso',
                        request=request,
                        detalle=f'Logout manual - Token blacklisted: {token_blacklisted}'
                    )
                    logger.info(f"Logout exitoso para usuario: {user.username}")
                else:
                    SecurityUtils.create_audit_event(
                        usuario=None,
                        username='anonymous',
                        evento='logout_exitoso',
                        request=request,
                        detalle='Logout sin usuario autenticado'
                    )
            except Exception as e:
                logger.error(f"Error creando evento de auditoría en logout: {e}")
            
            # Agregar información adicional a la respuesta
            response_data.update({
                "token_invalidated": token_blacklisted,
                "user_was_authenticated": user.is_authenticated if user else False
            })
            
            # SIEMPRE retornar 200 OK para que frontend pueda limpiar tokens
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error en LogoutAPIView: {e}")
            # Incluso con errores, permitir que el frontend limpie tokens
            return Response({
                "success": True,  # True para permitir limpieza en frontend
                "message": "Sesión cerrada (con advertencias)",
                "warning": "Algunas operaciones de limpieza podrían haber fallado",
                "timestamp": timezone.now().isoformat(),
                "next_action": "redirect_to_login"
            }, status=status.HTTP_200_OK)

class LogoutAllSessionsAPIView(APIView):
    """
    API para logout masivo - Cierra todas las sesiones del usuario
    Útil para cambios de contraseña o actividad sospechosa
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """Cerrar todas las sesiones activas del usuario"""
        try:
            user = request.user
            blacklisted_count = 0
            total_tokens = 0
            
            # Obtener y blacklistear todos los refresh tokens del usuario
            try:
                outstanding_tokens = OutstandingToken.objects.filter(user=user)
                total_tokens = outstanding_tokens.count()
                
                # Procesar tokens en lotes para mejor rendimiento
                for token_obj in outstanding_tokens:
                    try:
                        refresh_token = RefreshToken(token_obj.token)
                        refresh_token.blacklist()
                        blacklisted_count += 1
                    except Exception as e:
                        logger.warning(f"Error blacklisting token {token_obj.id}: {e}")
                        continue  # Token ya blacklisted o inválido
                        
            except Exception as e:
                logger.error(f"Error obteniendo tokens para usuario {user.username}: {e}")
            
            # Crear evento de auditoría
            SecurityUtils.create_audit_event(
                usuario=user,
                username=user.username,
                evento='logout_exitoso',
                request=request,
                detalle=f'Logout masivo - {blacklisted_count}/{total_tokens} sesiones cerradas'
            )
            
            logger.info(f"Logout masivo para {user.username}: {blacklisted_count}/{total_tokens} tokens blacklisted")
            
            # Determinar estado de la operación
            if blacklisted_count == total_tokens and total_tokens > 0:
                status_msg = "success"
                message = "Todas las sesiones han sido cerradas exitosamente"
            elif blacklisted_count > 0:
                status_msg = "partial_success"
                message = f"Se cerraron {blacklisted_count} de {total_tokens} sesiones"
            else:
                status_msg = "no_sessions"
                message = "No se encontraron sesiones activas para cerrar"
            
            return Response({
                "success": True,
                "message": message,
                "details": {
                    "sessions_closed": blacklisted_count,
                    "total_sessions_found": total_tokens,
                    "status": status_msg
                },
                "recommendations": [
                    "Cierra y vuelve a abrir tu navegador",
                    "Vuelve a iniciar sesión en todos tus dispositivos"
                ],
                "next_action": "redirect_to_login"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error en LogoutAllSessionsAPIView: {e}")
            
            # Aún así, crear evento de auditoría
            try:
                SecurityUtils.create_audit_event(
                    usuario=request.user,
                    username=request.user.username,
                    evento='logout_exitoso',
                    request=request,
                    detalle=f'Logout masivo fallido: {str(e)}'
                )
            except Exception:
                pass
            
            return Response({
                "success": False,
                "message": "Error durante el cierre masivo de sesiones",
                "recommendation": "Intenta cerrar sesión manualmente desde todos tus dispositivos",
                "next_action": "redirect_to_login"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UsuarioRawAPIView(APIView):
    """
    API para consultas SQL raw de usuarios (Solo para debugging/admin)
    ADVERTENCIA: Esta vista debe ser eliminada en producción
    """
    permission_classes = [IsAuthenticated]  # Solo usuarios autenticados
    
    def get(self, request):
        """Obtener datos de usuario usando SQL raw (SOLO PARA DESARROLLO)"""
        try:
            # Verificar que solo staff pueda usar esta vista
            if not request.user.is_staff:
                return Response(
                    {"error": "Permisos insuficientes"}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            username = request.query_params.get('username', '').strip()
            
            if not username:
                return Response(
                    {"error": "Username es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Consulta SQL protegida con parámetros
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT u.id, u.username, u.email, u.is_active, u.is_email_verified,
                           u.two_factor_enabled, u.failed_login_attempts,
                           p.nombre, p.apellido, p.ci
                    FROM usuarios_usuario u
                    LEFT JOIN usuarios_persona p ON u.persona_id = p.id_persona
                    WHERE u.username = %s
                    """, 
                    [username]
                )
                row = cursor.fetchone()
                columns = [col[0] for col in cursor.description]
            
            if row:
                usuario_dict = dict(zip(columns, row))
                
                # Crear evento de auditoría para esta consulta sensible
                SecurityUtils.create_audit_event(
                    usuario=request.user,
                    username=request.user.username,
                    evento='acceso_no_autorizado',  # Marcar como sensible
                    request=request,
                    detalle=f'Consulta SQL raw de usuario: {username}'
                )
                
                return Response({
                    "usuario": usuario_dict,
                    "warning": "Esta es una vista de desarrollo - No usar en producción",
                    "consulted_by": request.user.username
                }, status=status.HTTP_200_OK)
            else:
                return Response(
                    {"error": "Usuario no encontrado"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
                
        except Exception as e:
            logger.error(f"Error en UsuarioRawAPIView: {e}")
            return Response(
                {"error": "Error en consulta SQL"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# ============================================================================
# NOTAS DE IMPLEMENTACIÓN Y MEJORAS FUTURAS
# ============================================================================

"""
IMPLEMENTACIÓN DE BIOMETRÍA COMO SEGUNDO FACTOR:

1. REGISTRO DE DATOS BIOMÉTRICOS:
   - El usuario registra sus datos biométricos (huella, rostro, etc.) en el sistema
   - Los datos se almacenan encriptados en el modelo Biometricos
   - Se utiliza el campo correspondiente (huellas_encrypted, rostro_encrypted, etc.)

2. PROCESO DE AUTENTICACIÓN:
   - Tras validar credenciales, solicitar biometría al frontend
   - El frontend utiliza APIs nativas (WebAuthn, sensores del dispositivo, etc.)
   - El frontend envía la información biométrica al backend

3. VALIDACIÓN EN BACKEND:
   - El backend desencripta los datos almacenados
   - Compara la biometría recibida con la almacenada
   - Si coincide, permite el acceso y genera tokens JWT

4. CONSIDERACIONES TÉCNICAS:
   - Implementación depende del hardware disponible
   - Soporte del navegador/dispositivo para WebAuthn
   - Fallback a 2FA tradicional si biometría no está disponible
   - Encriptación robusta de datos biométricos

MEJORAS DE SEGURIDAD RECOMENDADAS:
- Implementar rate limiting por IP
- Añadir CAPTCHA tras múltiples intentos fallidos
- Implementar notificaciones de seguridad por email
- Agregar geolocalización de intentos de login
- Implementar whitelist/blacklist de IPs
- Añadir detección de dispositivos conocidos

OPTIMIZACIONES DE RENDIMIENTO:
- Implementar cache Redis para consultas frecuentes
- Optimizar queries con índices de base de datos
- Implementar paginación en todas las listas
- Usar conexiones de BD asíncronas cuando sea posible
- Implementar compresión de respuestas API

MONITOREO Y OBSERVABILIDAD:
- Implementar métricas de performance (APM)
- Agregar alertas para actividad sospechosa
- Implementar dashboard de auditoría en tiempo real
- Añadir logs estructurados con ELK stack
- Implementar health checks para todas las APIs
"""

class AccountStatusAPIView(APIView):
    """
    API para consultar estado de cuenta de usuario
    Incluye información de bloqueos y intentos fallidos
    """
    permission_classes = [AllowAny]  # Necesario para login flow
    
    def get(self, request):
        """Obtener estado actual de la cuenta"""
        try:
            username = request.query_params.get('username', '').strip()
            
            if not username:
                return Response(
                    {"error": "Username es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                # Buscar usuario con optimización
                usuario = Usuario.objects.select_related('persona').get(username=username)
                
                # Limpiar bloqueo si ya expiró
                is_locked = SecurityUtils.check_account_lockout(usuario)
                
                # Preparar información de estado
                status_info = {
                    "username": usuario.username,
                    "is_active": usuario.is_active,
                    "is_email_verified": usuario.is_email_verified,
                    "two_factor_enabled": usuario.two_factor_enabled,
                    "failed_login_attempts": usuario.failed_login_attempts,
                    "max_attempts_allowed": SecurityConfig.MAX_LOGIN_ATTEMPTS,
                    "account_locked": is_locked
                }
                
                # Agregar información de bloqueo si aplica
                if is_locked and usuario.account_locked_until:
                    locked_until_local = timezone.localtime(usuario.account_locked_until)
                    tiempo_restante = usuario.account_locked_until - timezone.now()
                    
                    status_info.update({
                        "locked_until": locked_until_local.strftime('%Y-%m-%d %H:%M:%S'),
                        "locked_until_iso": usuario.account_locked_until.isoformat(),
                        "minutes_remaining": max(0, int(tiempo_restante.total_seconds() / 60)),
                        "lockout_reason": "Múltiples intentos de login fallidos"
                    })
                
                # Agregar recomendaciones basadas en el estado
                recommendations = []
                if not usuario.is_email_verified:
                    recommendations.append("Verifica tu correo electrónico antes de iniciar sesión")
                if is_locked:
                    recommendations.append(f"Espera {status_info.get('minutes_remaining', 0)} minutos antes de intentar nuevamente")
                if usuario.failed_login_attempts > 0 and not is_locked:
                    remaining = SecurityConfig.MAX_LOGIN_ATTEMPTS - usuario.failed_login_attempts
                    recommendations.append(f"Tienes {remaining} intentos restantes antes del bloqueo")
                
                if recommendations:
                    status_info['recommendations'] = recommendations
                
                # Log de consulta de estado (solo para debugging, no auditoría completa)
                logger.debug(f"Consulta de estado para usuario: {username}")
                
                return Response(status_info, status=status.HTTP_200_OK)
                
            except Usuario.DoesNotExist:
                # Por seguridad, no revelar que el usuario no existe
                return Response({
                    "error": "Usuario no encontrado",
                    "recommendation": "Verifica que el username sea correcto"
                }, status=status.HTTP_404_NOT_FOUND)
                
        except Exception as e:
            logger.error(f"Error en AccountStatusAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ===== NUEVAS VISTAS PARA VERIFICACIÓN DE EMAIL =====

class VerificarEmailAPIView(APIView):
    """
    API para verificar email con código de verificación
    Activa la cuenta del usuario tras verificación exitosa
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Verificar código de verificación de email"""
        try:
            # Validar datos de entrada
            email = request.data.get('email', '').strip().lower()
            codigo = request.data.get('codigo', '').strip()
            
            if not email:
                return Response(
                    {"error": "Email es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not codigo:
                return Response(
                    {"error": "Código de verificación es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                # Buscar usuario por email y código con optimización
                usuario = Usuario.objects.select_related('persona').get(
                    email=email,
                    email_verification_token=codigo
                )
                
                # Verificar si el código ha expirado
                if (usuario.email_verification_expires and 
                    timezone.now() > usuario.email_verification_expires):
                    
                    SecurityUtils.create_audit_event(
                        usuario=usuario,
                        username=usuario.username,
                        evento='acceso_no_autorizado',
                        request=request,
                        detalle='Intento de verificación con código expirado'
                    )
                    
                    return Response({
                        "error": "Código de verificación expirado",
                        "message": "El código ha expirado. Solicita un nuevo correo de verificación",
                        "expired": True,
                        "resend_endpoint": "/api/usuarios/reenviar-verificacion/"
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Verificar email dentro de transacción
                with transaction.atomic():
                    usuario.is_email_verified = True
                    usuario.email_verification_token = None
                    usuario.email_verification_expires = None
                    # Resetear intentos fallidos por seguridad
                    usuario.failed_login_attempts = 0
                    usuario.account_locked_until = None
                    usuario.save()
                
                # Crear evento de auditoría
                SecurityUtils.create_audit_event(
                    usuario=usuario,
                    username=usuario.username,
                    evento='login_exitoso',  # Usar evento existente o crear uno nuevo
                    request=request,
                    detalle='Email verificado exitosamente'
                )
                
                logger.info(f"Email verificado exitosamente para usuario: {usuario.username}")
                
                # Enviar email de bienvenida
                try:
                    send_mail(
                        "¡Bienvenido a EdificioApp!",
                        f"""
                        ¡Hola {usuario.persona.nombre}!
                        
                        ¡Tu cuenta ha sido verificada exitosamente!
                        
                        Ya puedes acceder a todas las funcionalidades de EdificioApp.
                        
                        Saludos,
                        El equipo de EdificioApp
                        """,
                        settings.DEFAULT_FROM_EMAIL,
                        [usuario.email],
                        fail_silently=True,
                    )
                except Exception as e:
                    logger.error(f"Error enviando email de bienvenida: {e}")
                
                return Response({
                    "success": True,
                    "message": Messages.EMAIL_VERIFIED,
                    "user_info": {
                        "username": usuario.username,
                        "email": usuario.email,
                        "nombre_completo": f"{usuario.persona.nombre} {usuario.persona.apellido}",
                        "verified": True
                    },
                    "next_steps": {
                        "action": "login",
                        "description": "Ahora puedes iniciar sesión con normalidad",
                        "login_endpoint": "/api/usuarios/login/"
                    }
                }, status=status.HTTP_200_OK)
                
            except Usuario.DoesNotExist:
                # Email o código inválido
                SecurityUtils.create_audit_event(
                    usuario=None,
                    username='',
                    evento='acceso_no_autorizado',
                    request=request,
                    detalle=f'Intento de verificación con email o código inválido: {email}'
                )
                
                return Response({
                    "error": "Email o código de verificación inválido",
                    "suggestions": [
                        "Verifica que el email sea correcto",
                        "Verifica que el código sea correcto (6 dígitos)",
                        "Solicita un nuevo código si el actual expiró"
                    ],
                    "resend_endpoint": "/api/usuarios/reenviar-verificacion/"
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Error en VerificarEmailAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ReenviarVerificacionAPIView(APIView):
    """
    API para reenviar correo de verificación
    Útil cuando el código anterior expiró
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Reenviar código de verificación por email"""
        try:
            email = request.data.get('email', '').strip().lower()
            
            if not email:
                return Response(
                    {"error": "Email es requerido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validación básica de email
            if '@' not in email or '.' not in email:
                return Response(
                    {"error": "Formato de email inválido"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                # Buscar usuario con optimización
                usuario = Usuario.objects.select_related('persona').get(email=email)
                
                # Verificar si ya está verificado
                if usuario.is_email_verified:
                    return Response({
                        "success": True,
                        "message": "El email ya está verificado",
                        "status": "already_verified",
                        "next_steps": {
                            "action": "login",
                            "description": "Puedes iniciar sesión normalmente",
                            "login_endpoint": "/api/usuarios/login/"
                        }
                    }, status=status.HTTP_200_OK)
                
                # Generar nuevo código y enviar correo
                email_sent = EmailUtils.send_verification_email(usuario)
                
                if not email_sent:
                    return Response(
                        {"error": "Error enviando correo de verificación"}, 
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
                
                # Crear evento de auditoría
                SecurityUtils.create_audit_event(
                    usuario=usuario,
                    username=usuario.username,
                    evento='login_exitoso',  # Usar evento existente
                    request=request,
                    detalle='Reenvío de código de verificación solicitado'
                )
                
                logger.info(f"Código de verificación reenviado a: {email}")
                
                return Response({
                    "success": True,
                    "message": "Código de verificación reenviado exitosamente",
                    "details": {
                        "email_sent_to": usuario.email,
                        "expires_in": "24 horas",
                        "code_type": "6 dígitos numéricos"
                    },
                    "next_steps": {
                        "action": "verify_email",
                        "description": "Revisa tu bandeja de entrada e ingresa el nuevo código",
                        "verify_endpoint": "/api/usuarios/verificar-email/"
                    }
                }, status=status.HTTP_200_OK)
                
            except Usuario.DoesNotExist:
                # Por seguridad, simular respuesta exitosa para evitar enumeración
                SecurityUtils.create_audit_event(
                    usuario=None,
                    username='',
                    evento='acceso_no_autorizado',
                    request=request,
                    detalle=f'Solicitud de reenvío con email inexistente: {email}'
                )
                
                # Simular tiempo de procesamiento
                import time
                time.sleep(1)
                
                return Response({
                    "success": True,
                    "message": "Si el email existe, recibirás un nuevo código de verificación",
                    "note": "Por seguridad, no confirmamos si el email existe en nuestro sistema"
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            logger.error(f"Error en ReenviarVerificacionAPIView: {e}")
            return Response(
                {"error": "Error interno del servidor"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )