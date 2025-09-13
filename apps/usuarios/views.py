from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from .serializers import RegisterSerializer, LoginSerializer
from .models import Usuario, Persona
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.permissions import IsAuthenticated
import uuid

class RegisterAPIView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            usuario = serializer.save()
            # Ya no se genera ni envía token de verificación
            usuario.is_email_verified = True  # Se marca como verificado automáticamente
            usuario.save()
            return Response({
                "id_usuario": usuario.id_usuario,
                "username": usuario.username,
                "message": "Usuario creado correctamente."
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Eliminada la clase VerifyEmailAPIView

class LoginAPIView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            usuario = serializer.validated_data["usuario"]
            # Ya no se valida is_email_verified
            # Generar SIEMPRE un nuevo token de login y guardar (el anterior queda inválido)
            login_token = str(uuid.uuid4())
            usuario.login_token = login_token
            usuario.save()
            # Enviar el token por correo
            send_mail(
                "Token de acceso",
                f"Tu token de acceso para iniciar sesión es: {login_token}",
                settings.DEFAULT_FROM_EMAIL,
                [usuario.email],
            )
            return Response({
                "msg": "Se ha enviado un token de acceso a tu correo. Ingresa el token para completar el login.",
                "username": usuario.username
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            usuario = Usuario.objects.get(email=email)
            token = str(uuid.uuid4())
            usuario.reset_password_token = token
            usuario.save()
            # Enviar solo el token por correo
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
            usuario.set_password(new_password)
            usuario.reset_password_token = None
            usuario.save()
            return Response({"msg": "Contraseña restablecida."})
        except Usuario.DoesNotExist:
            return Response({"error": "Token inválido."}, status=400)

class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        new_password = request.data.get('new_password')
        user.set_password(new_password)
        user.save()
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
                # Invalida el token después de usarlo
                usuario.login_token = None
                usuario.save()
                # Aquí puedes generar y retornar el JWT si usas JWT
                refresh = RefreshToken.for_user(usuario)
                return Response({
                    "message": "Login exitoso",
                    "id_usuario": usuario.id_usuario,
                    "username": usuario.username,
                    "refresh": str(refresh),
                    "access": str(refresh.access_token)
                }, status=status.HTTP_200_OK)
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