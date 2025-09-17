from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from .serializers import RegisterSerializer, LoginSerializer, AuditoriaEventoSerializer, validar_password
from .models import Usuario, Persona
from .models import AuditoriaEvento
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

# --- 2FA imports ---
import pyotp
import qrcode
import io
from django.http import HttpResponse

# --- SQL crudo seguro ---
from django.db import connection

class Activate2FAAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user.two_factor_secret:
            secret = pyotp.random_base32()
            user.two_factor_secret = secret
            user.save()
        else:
            secret = user.two_factor_secret

        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="EdificioApp"
        )
        img = qrcode.make(otp_uri)
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0)
        return HttpResponse(buf, content_type='image/png')

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
                refresh = RefreshToken.for_user(user)
                return Response({
                    "msg": "2FA verificado correctamente.",
                    "access": str(refresh.access_token),
                    "refresh": str(refresh)
                })
            else:
                return Response({"error": "Código inválido."}, status=400)
        except Usuario.DoesNotExist:
            return Response({"error": "Usuario no encontrado."}, status=400)

class RegisterAPIView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            usuario = serializer.save()
            usuario.is_email_verified = True
            usuario.save()
            return Response({
                "id_usuario": usuario.id,
                "username": usuario.username,
                "message": "Usuario creado correctamente."
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Eliminada la clase VerifyEmailAPIView

class LoginAPIView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        username = request.data.get('username', '')
        ip = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        usuario = Usuario.objects.filter(username=username).first()
        if usuario:
            # Si la cuenta está bloqueada y el tiempo ya pasó, resetea el contador y desbloquea
            if usuario.account_locked_until and usuario.account_locked_until <= timezone.now():
                usuario.failed_login_attempts = 0
                usuario.account_locked_until = None
                usuario.save()
            # Si la cuenta sigue bloqueada, no permite login
            elif usuario.account_locked_until and usuario.account_locked_until > timezone.now():
                return Response({
                    "error": "Cuenta bloqueada por demasiados intentos fallidos. Intenta de nuevo en unos minutos."
                }, status=status.HTTP_403_FORBIDDEN)

        if serializer.is_valid():
            usuario = serializer.validated_data["usuario"]
            # Resetear intentos fallidos al login exitoso
            usuario.failed_login_attempts = 0
            usuario.account_locked_until = None
            usuario.save()
            login_token = str(uuid.uuid4())
            usuario.login_token = login_token
            usuario.save()
            send_mail(
                "Token de acceso",
                f"Tu token de acceso para iniciar sesión es: {login_token}",
                settings.DEFAULT_FROM_EMAIL,
                [usuario.email],
            )
            AuditoriaEvento.objects.create(
                usuario=usuario,
                username=usuario.username,
                evento='login_exitoso',
                ip=ip,
                user_agent=user_agent,
                detalle='Login correcto'
            )
            return Response({
                "msg": "Se ha enviado un token de acceso a tu correo. Ingresa el token para completar el login.",
                "username": usuario.username
            }, status=status.HTTP_200_OK)
        else:
            # Si el usuario existe, incrementa el contador de intentos fallidos
            if usuario:
                usuario.failed_login_attempts += 1
                # Si supera el límite, bloquea la cuenta por 1 minuto (ajusta el tiempo si lo deseas)
                if usuario.failed_login_attempts >= 5:
                    usuario.account_locked_until = timezone.now() + timedelta(minutes=1)
                usuario.save()
            AuditoriaEvento.objects.create(
                usuario=None,
                username=username,
                evento='login_fallido',
                ip=ip,
                user_agent=user_agent,
                detalle=str(serializer.errors)
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            usuario = Usuario.objects.get(email=email)
            token = str(uuid.uuid4())
            usuario.reset_password_token = token
            usuario.save()
            send_mail(
                "Recupera tu contraseña",
                f"Tu token para restablecer la contraseña es: {token}",
                settings.DEFAULT_FROM_EMAIL,
                [usuario.email],
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
            usuario.reset_password_token = None
            usuario.save()
            ip = request.META.get('REMOTE_ADDR')
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            AuditoriaEvento.objects.create(
                usuario=usuario,
                username=usuario.username,
                evento='reset_password',
                ip=ip,
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
        user.set_password(new_password)
        user.save()
        ip = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        AuditoriaEvento.objects.create(
            usuario=user,
            username=user.username,
            evento='cambio_password',
            ip=ip,
            user_agent=user_agent,
            detalle='Cambio de contraseña exitoso'
        )
        return Response({"msg": "Contraseña cambiada correctamente."})

class ValidateLoginTokenAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        token = request.data.get('token')
        if not username or not token:
            return Response({"error": "Username y token requeridos."}, status=400)
        try:
            usuario = Usuario.objects.get(username=username)
            if usuario.login_token == token:
                usuario.login_token = None
                usuario.save()
                # Verifica si tiene 2FA activado
                if not usuario.two_factor_enabled:
                    # Genera el QR y responde con la URL/base64
                    import pyotp, qrcode, io
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
                    qr_url = f"data:image/png;base64,{img_base64}"
                    return Response({"qr_url": qr_url})
                else:
                    # Si ya tiene 2FA activado, pide el código 2FA
                    return Response({"require_2fa": True})
            else:
                return Response({"error": "Token inválido."}, status=400)
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
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"msg": "Sesión cerrada correctamente."}, status=200)
        except Exception as e:
            return Response({"error": "Token inválido o ya caducado."}, status=400)

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
            return Response({
                "account_locked_until": usuario.account_locked_until,
                "failed_login_attempts": usuario.failed_login_attempts
            })
        except Usuario.DoesNotExist:
            return Response({"error": "Usuario no encontrado"}, status=404)