# ============================================================================
# SERIALIZERS - Validaciones y transformaciones de datos
# ============================================================================

# Python standard library
import logging
import random
import re
from datetime import timedelta
from typing import Dict, Any, Optional, List

# Django core
from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

# Django REST Framework
from rest_framework import serializers

# Third party packages
import bleach

# Local imports
from .models import Persona, Usuario, AuditoriaEvento
from .crypto import encrypt_sensitive_data, decrypt_sensitive_data

# ============================================================================
# CONFIGURACIÓN DE LOGGING
# ============================================================================
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTES Y CONFIGURACIONES
# ============================================================================

class PasswordValidationConfig:
    """Configuraciones para validación de contraseñas"""
    MIN_LENGTH = 8
    RECOMMENDED_LENGTH = 12
    MAX_PERSONAL_INFO_LENGTH = 3
    MAX_DATE_YEAR_LENGTH = 4
    
    # Patrones de regex precompilados para mejor rendimiento
    UPPERCASE_PATTERN = re.compile(r"[A-Z]")
    LOWERCASE_PATTERN = re.compile(r"[a-z]")
    NUMBER_PATTERN = re.compile(r"[0-9]")
    SPECIAL_CHAR_PATTERN = re.compile(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\\/~`]")
    SEQUENTIAL_PATTERN = re.compile(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)")
    REPEATED_CHAR_PATTERN = re.compile(r"(.)\1{2,}")

class ValidationMessages:
    """Mensajes de validación centralizados"""
    PASSWORD_TOO_SHORT = "La contraseña debe tener al menos {min_length} caracteres. Recomendamos {recommended_length} o más para mayor seguridad."
    PASSWORD_NO_UPPERCASE = "La contraseña debe contener al menos una letra mayúscula (A-Z)."
    PASSWORD_NO_LOWERCASE = "La contraseña debe contener al menos una letra minúscula (a-z)."
    PASSWORD_NO_NUMBER = "La contraseña debe contener al menos un número (0-9)."
    PASSWORD_NO_SPECIAL = "La contraseña debe contener al menos un carácter especial (!@#$%^&*(),.?\":{}|<>_-+=[]\\\/~`)."
    PASSWORD_TOO_COMMON = "La contraseña es demasiado común. Por favor, elige una contraseña más original y segura."
    PASSWORD_PERSONAL_INFO = "La contraseña no debe contener tu información personal (nombre, apellido, CI o fecha de nacimiento). Esto hace que sea más fácil de adivinar."
    PASSWORD_SEQUENTIAL = "La contraseña no debe contener secuencias obvias como '123' o 'abc'."
    PASSWORD_REPEATED_CHARS = "La contraseña no debe tener más de 2 caracteres iguales consecutivos."
    
    # Mensajes de duplicados
    CI_EXISTS = "Ya existe una persona registrada con este CI."
    EMAIL_EXISTS = "Ya existe una persona registrada con este email."
    USERNAME_EXISTS = "Ya existe un usuario con este username. Por favor, elige otro."
    
    # Mensajes de login
    USER_NOT_FOUND = "No existe un usuario con ese nombre de usuario."
    INCORRECT_PASSWORD = "La contraseña ingresada es incorrecta."
    EMAIL_NOT_VERIFIED = "Debes verificar tu correo electrónico antes de iniciar sesión."

# Lista expandida de contraseñas comunes - basada en estudios de seguridad reales
COMMON_PASSWORDS = frozenset([  # frozenset para mejor rendimiento en búsquedas
    # Top 15 más comunes mundialmente (actualizadas 2024-2025)
    "123456", "password", "12345678", "qwerty", "abc123", "111111", 
    "123456789", "12345", "123123", "admin", "welcome", "monkey",
    "1234567890", "dragon", "superman",
    
    # Variaciones comunes en español/latinoamérica
    "contraseña", "clave123", "admin123", "usuario", "edificio", "portero", 
    "conserje", "administrador", "secreto", "privado", "seguridad123",
    
    # Patrones comunes con años
    "password123", "qwerty123", "admin2023", "admin2024", "admin2025",
    "password2024", "password2025", "user2024", "user2025",
    
    # Específicas del contexto de edificios
    "edificio123", "porteria", "acceso", "seguridad", "entrada",
    "residencia", "condominio", "apartamento", "casa123", "hogar",
    "building", "tower", "residence",
    
    # Patrones de teclado
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "qwerty12", "asdf1234",
    
    # Palabras en inglés comunes
    "welcome123", "hello123", "computer", "internet", "master",
    "access", "login", "system", "default", "guest"
])

# ============================================================================
# UTILIDADES DE VALIDACIÓN
# ============================================================================

class PasswordValidator:
    """Validador de contraseñas centralizado y optimizado"""
    
    @staticmethod
    def validate_length(password: str) -> None:
        """Validar longitud mínima de contraseña"""
        if len(password) < PasswordValidationConfig.MIN_LENGTH:
            raise serializers.ValidationError(
                ValidationMessages.PASSWORD_TOO_SHORT.format(
                    min_length=PasswordValidationConfig.MIN_LENGTH,
                    recommended_length=PasswordValidationConfig.RECOMMENDED_LENGTH
                )
            )
    
    @staticmethod
    def validate_character_requirements(password: str) -> None:
        """Validar que la contraseña tenga todos los tipos de caracteres requeridos"""
        if not PasswordValidationConfig.UPPERCASE_PATTERN.search(password):
            raise serializers.ValidationError(ValidationMessages.PASSWORD_NO_UPPERCASE)
        
        if not PasswordValidationConfig.LOWERCASE_PATTERN.search(password):
            raise serializers.ValidationError(ValidationMessages.PASSWORD_NO_LOWERCASE)
        
        if not PasswordValidationConfig.NUMBER_PATTERN.search(password):
            raise serializers.ValidationError(ValidationMessages.PASSWORD_NO_NUMBER)
        
        if not PasswordValidationConfig.SPECIAL_CHAR_PATTERN.search(password):
            raise serializers.ValidationError(ValidationMessages.PASSWORD_NO_SPECIAL)
    
    @staticmethod
    def validate_common_passwords(password: str) -> None:
        """Validar que no sea una contraseña común"""
        if password.lower() in COMMON_PASSWORDS:
            raise serializers.ValidationError(ValidationMessages.PASSWORD_TOO_COMMON)
    
    @staticmethod
    def validate_personal_info(password: str, nombre: str = '', apellido: str = '', 
                             ci: str = '', fecha_nacimiento: Any = None) -> None:
        """Validar que no contenga información personal"""
        personal_info = []
        password_lower = password.lower()
        
        # Agregar nombre y apellido si tienen longitud suficiente
        if nombre and len(nombre) >= PasswordValidationConfig.MAX_PERSONAL_INFO_LENGTH:
            personal_info.append(nombre.lower())
        if apellido and len(apellido) >= PasswordValidationConfig.MAX_PERSONAL_INFO_LENGTH:
            personal_info.append(apellido.lower())
        
        # Agregar CI si tiene longitud suficiente
        if ci and len(ci) >= PasswordValidationConfig.MAX_PERSONAL_INFO_LENGTH:
            personal_info.append(ci.lower())
        
        # Procesar fecha de nacimiento en diferentes formatos
        if fecha_nacimiento:
            fecha_str = str(fecha_nacimiento)
            personal_info.extend([
                fecha_str.lower(),  # Formato completo
                fecha_str.replace('-', '').lower(),  # Sin guiones
                fecha_str.replace('/', '').lower(),  # Sin barras
                fecha_str.replace('.', '').lower(),  # Sin puntos
            ])
            
            # Agregar solo el año si tiene longitud suficiente
            if len(fecha_str) >= PasswordValidationConfig.MAX_DATE_YEAR_LENGTH:
                year = fecha_str[-4:]
                if year.isdigit():
                    personal_info.append(year)
        
        # Verificar si alguna información personal está en la contraseña
        for info in personal_info:
            if info and len(info) >= PasswordValidationConfig.MAX_PERSONAL_INFO_LENGTH:
                if info in password_lower:
                    raise serializers.ValidationError(ValidationMessages.PASSWORD_PERSONAL_INFO)
    
    @staticmethod
    def validate_patterns(password: str) -> None:
        """Validar patrones problemáticos en la contraseña"""
        # Validar secuencias obvias
        if PasswordValidationConfig.SEQUENTIAL_PATTERN.search(password.lower()):
            raise serializers.ValidationError(ValidationMessages.PASSWORD_SEQUENTIAL)
        
        # Validar caracteres repetidos
        if PasswordValidationConfig.REPEATED_CHAR_PATTERN.search(password):
            raise serializers.ValidationError(ValidationMessages.PASSWORD_REPEATED_CHARS)
    
    @classmethod
    def validate_full(cls, password: str, nombre: str = '', apellido: str = '', 
                     ci: str = '', fecha_nacimiento: Any = None) -> None:
        """Ejecutar todas las validaciones de contraseña"""
        try:
            cls.validate_length(password)
            cls.validate_character_requirements(password)
            cls.validate_common_passwords(password)
            cls.validate_personal_info(password, nombre, apellido, ci, fecha_nacimiento)
            cls.validate_patterns(password)
            
            logger.debug(f"Contraseña validada exitosamente para usuario")
            
        except serializers.ValidationError as e:
            logger.warning(f"Validação de contraseña fallida: {str(e)}")
            raise

def validar_password(password: str, nombre: str = '', apellido: str = '', 
                    ci: str = '', fecha_nacimiento: Any = None) -> None:
    """
    Función de validación de contraseñas (wrapper para compatibilidad)
    
    Esta función mantiene la compatibilidad con el código existente
    delegando a la clase PasswordValidator optimizada.
    
    Args:
        password (str): Contraseña a validar
        nombre (str): Nombre del usuario (opcional)
        apellido (str): Apellido del usuario (opcional)  
        ci (str): CI del usuario (opcional)
        fecha_nacimiento (Any): Fecha de nacimiento (opcional)
    
    Raises:
        serializers.ValidationError: Si la contraseña no cumple los criterios
    """
    PasswordValidator.validate_full(password, nombre, apellido, ci, fecha_nacimiento)

# ============================================================================
# UTILIDADES DE EMAIL Y COMUNICACIÓN
# ============================================================================

class EmailService:
    """Servicio centralizado para envío de correos electrónicos"""
    
    @staticmethod
    def send_verification_email(usuario: Usuario) -> bool:
        """
        Envía correo de verificación al usuario
        
        Args:
            usuario (Usuario): Usuario al que enviar el correo
            
        Returns:
            bool: True si se envió exitosamente, False en caso contrario
        """
        try:
            subject = "Código de verificación - EdificioApp"
            
            message = f"""
            ¡Hola {usuario.persona.nombre}!
            
            Gracias por registrarte en EdificioApp. Para completar tu registro, 
            por favor ingresa el siguiente código de verificación en la aplicación:
            
            ┌─────────────────────────────────┐
            │  CÓDIGO: {usuario.email_verification_token}  │
            └─────────────────────────────────┘
            
            Este código expirará en 24 horas por seguridad.
            
            Si no creaste esta cuenta, puedes ignorar este correo.
            
            Saludos,
            El equipo de EdificioApp
            """
            
            logger.info(f"🔄 Enviando correo de verificación a: {usuario.email}")
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [usuario.email],
                fail_silently=False,
            )
            
            logger.info(f"✅ Correo de verificación enviado exitosamente a: {usuario.email}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error enviando correo de verificación a {usuario.email}: {e}")
            logger.error(f"📧 Configuración - Backend: {settings.EMAIL_BACKEND}")
            logger.error(f"📧 Configuración - From: {settings.DEFAULT_FROM_EMAIL}")
            return False

# ============================================================================
# SERIALIZERS OPTIMIZADOS
# ============================================================================

class PersonaSerializer(serializers.ModelSerializer):
    """
    Serializer para el modelo Persona con validaciones mejoradas
    Incluye sanitización de datos y validaciones robustas
    """
    
    # Campos con validaciones específicas
    nombre = serializers.CharField(
        max_length=50,
        min_length=2,
        help_text="Nombre de la persona (2-50 caracteres)"
    )
    apellido = serializers.CharField(
        max_length=50,
        min_length=2,
        help_text="Apellido de la persona (2-50 caracteres)"
    )
    ci = serializers.CharField(
        max_length=20,
        min_length=5,
        help_text="Cédula de identidad (5-20 caracteres)"
    )
    email = serializers.EmailField(
        help_text="Correo electrónico válido"
    )
    telefono = serializers.CharField(
        max_length=20,
        min_length=7,
        required=False,
        allow_blank=True,
        help_text="Número de teléfono (7-20 caracteres, opcional)"
    )
    
    class Meta:
        model = Persona
        fields = [
            "nombre", "apellido", "ci", "email", 
            "sexo", "telefono", "fecha_nacimiento"
        ]
        extra_kwargs = {
            'sexo': {
                'required': False,
                'allow_blank': True,
                'help_text': 'Sexo de la persona (opcional)'
            },
            'fecha_nacimiento': {
                'required': False,
                'allow_null': True,
                'help_text': 'Fecha de nacimiento (opcional, formato: YYYY-MM-DD)'
            }
        }
    
    def validate_nombre(self, value: str) -> str:
        """Validar y sanitizar nombre"""
        # Sanitizar HTML/scripts
        value = bleach.clean(value, tags=[], strip=True).strip()
        
        # Validar que solo contenga letras, espacios y acentos
        if not re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$", value):
            raise serializers.ValidationError(
                "El nombre solo debe contener letras, espacios y acentos."
            )
        
        # Validar que no tenga espacios múltiples
        if re.search(r"\s{2,}", value):
            raise serializers.ValidationError(
                "El nombre no debe tener espacios múltiples consecutivos."
            )
        
        return value.title()  # Capitalizar correctamente
    
    def validate_apellido(self, value: str) -> str:
        """Validar y sanitizar apellido"""
        # Sanitizar HTML/scripts
        value = bleach.clean(value, tags=[], strip=True).strip()
        
        # Validar que solo contenga letras, espacios y acentos
        if not re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$", value):
            raise serializers.ValidationError(
                "El apellido solo debe contener letras, espacios y acentos."
            )
        
        # Validar que no tenga espacios múltiples
        if re.search(r"\s{2,}", value):
            raise serializers.ValidationError(
                "El apellido no debe tener espacios múltiples consecutivos."
            )
        
        return value.title()  # Capitalizar correctamente
    
    def validate_ci(self, value: str) -> str:
        """Validar CI con formato específico"""
        # Sanitizar y limpiar
        value = bleach.clean(value, tags=[], strip=True).strip()
        
        # Remover espacios y caracteres especiales comunes
        value = re.sub(r"[\s\-\.]", "", value)
        
        # Validar que solo contenga números y/o letras (dependiendo del país)
        if not re.match(r"^[0-9A-Za-z]+$", value):
            raise serializers.ValidationError(
                "El CI solo debe contener números y letras, sin espacios ni caracteres especiales."
            )
        
        # Validar unicidad más tarde en validate()
        return value.upper()
    
    def validate_email(self, value: str) -> str:
        """Validar y normalizar email"""
        # Normalizar email (lowercase)
        value = value.lower().strip()
        
        # Sanitizar
        value = bleach.clean(value, tags=[], strip=True)
        
        # Validación adicional de formato
        email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        if not email_pattern.match(value):
            raise serializers.ValidationError(
                "Por favor, ingresa un formato de email válido."
            )
        
        return value
    
    def validate_telefono(self, value: str) -> str:
        """Validar formato de teléfono"""
        if not value:  # Campo opcional
            return value
        
        # Sanitizar
        value = bleach.clean(value, tags=[], strip=True).strip()
        
        # Remover espacios, guiones y paréntesis para validación
        clean_phone = re.sub(r"[\s\-\(\)\+]", "", value)
        
        # Validar que solo contenga números (después de limpiar)
        if not clean_phone.isdigit():
            raise serializers.ValidationError(
                "El teléfono solo debe contener números, espacios, guiones o paréntesis."
            )
        
        # Validar longitud del número limpio
        if len(clean_phone) < 7 or len(clean_phone) > 15:
            raise serializers.ValidationError(
                "El teléfono debe tener entre 7 y 15 dígitos."
            )
        
        return value
    
    def validate_fecha_nacimiento(self, value) -> Any:
        """Validar fecha de nacimiento"""
        if not value:  # Campo opcional
            return value
        
        # Validar que no sea fecha futura
        if value > timezone.now().date():
            raise serializers.ValidationError(
                "La fecha de nacimiento no puede ser en el futuro."
            )
        
        # Validar edad mínima (por ejemplo, 16 años)
        edad_minima = timezone.now().date().replace(year=timezone.now().year - 16)
        if value > edad_minima:
            raise serializers.ValidationError(
                "Debes tener al menos 16 años para registrarte."
            )
        
        # Validar edad máxima razonable (por ejemplo, 120 años)
        edad_maxima = timezone.now().date().replace(year=timezone.now().year - 120)
        if value < edad_maxima:
            raise serializers.ValidationError(
                "Por favor, verifica que la fecha de nacimiento sea correcta."
            )
        
        return value

class RegisterSerializer(serializers.Serializer):
    """
    Serializer para registro de nuevos usuarios
    Incluye validaciones cruzadas y creación transaccional
    """
    
    persona = PersonaSerializer()
    username = serializers.CharField(
        max_length=150,
        min_length=3,
        help_text="Nombre de usuario único (3-150 caracteres)"
    )
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        help_text="Contraseña segura (mínimo 8 caracteres)"
    )
    
    def validate_username(self, value: str) -> str:
        """Validar formato y disponibilidad del username"""
        # Sanitizar
        value = bleach.clean(value, tags=[], strip=True).strip()
        
        # Validar formato (solo letras, números, guiones y guiones bajos)
        if not re.match(r"^[a-zA-Z0-9_-]+$", value):
            raise serializers.ValidationError(
                "El username solo puede contener letras, números, guiones (-) y guiones bajos (_)."
            )
        
        # Validar que no empiece o termine con guión/guión bajo
        if value.startswith(('-', '_')) or value.endswith(('-', '_')):
            raise serializers.ValidationError(
                "El username no puede empezar o terminar con guión o guión bajo."
            )
        
        # Validar que no tenga caracteres consecutivos problemáticos
        if re.search(r"[-_]{2,}", value):
            raise serializers.ValidationError(
                "El username no puede tener guiones o guiones bajos consecutivos."
            )
        
        # Validar disponibilidad (se hace también en validate() pero aquí es más temprano)
        if Usuario.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError(ValidationMessages.USERNAME_EXISTS)
        
        return value.lower()  # Normalizar a minúsculas
    
    def validate_password(self, value: str) -> str:
        """Validar contraseña usando el validador optimizado"""
        # Usar el validador de contraseñas (sin información personal aún)
        PasswordValidator.validate_length(value)
        PasswordValidator.validate_character_requirements(value)
        PasswordValidator.validate_common_passwords(value)
        PasswordValidator.validate_patterns(value)
        
        return value
    
    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validaciones cruzadas entre campos"""
        try:
            # Extraer datos para validaciones
            persona_data = data['persona']
            ci = persona_data['ci']
            email = persona_data['email']
            password = data['password']
            username = data['username']
            nombre = persona_data['nombre']
            apellido = persona_data['apellido']
            fecha_nacimiento = persona_data.get('fecha_nacimiento')
            
            # Verificar unicidad de CI y email con consultas optimizadas
            existing_checks = []
            
            # Verificar CI
            if Persona.objects.filter(ci__iexact=ci).exists():
                existing_checks.append(('ci', ValidationMessages.CI_EXISTS))
            
            # Verificar email
            if Persona.objects.filter(email__iexact=email).exists():
                existing_checks.append(('email', ValidationMessages.EMAIL_EXISTS))
            
            # Verificar username (doble verificación por si acaso)
            if Usuario.objects.filter(username__iexact=username).exists():
                existing_checks.append(('username', ValidationMessages.USERNAME_EXISTS))
            
            # Si hay conflictos, reportarlos todos a la vez
            if existing_checks:
                error_dict = {field: message for field, message in existing_checks}
                raise serializers.ValidationError(error_dict)
            
            # Validar contraseña con información personal
            try:
                PasswordValidator.validate_personal_info(
                    password, nombre, apellido, ci, fecha_nacimiento
                )
            except serializers.ValidationError as e:
                raise serializers.ValidationError({'password': str(e)})
            
            # Validar que username no esté en la contraseña
            if username.lower() in password.lower():
                raise serializers.ValidationError({
                    'password': 'La contraseña no debe contener tu nombre de usuario.'
                })
            
            logger.debug(f"Validación de registro exitosa para username: {username}")
            return data
            
        except serializers.ValidationError:
            raise
        except Exception as e:
            logger.error(f"Error inesperado en validación de registro: {e}")
            raise serializers.ValidationError("Error interno de validación. Intenta nuevamente.")

    def create(self, validated_data: Dict[str, Any]) -> Usuario:
        """Crear usuario y persona de forma transaccional"""
        try:
            persona_data = validated_data.pop("persona")
            username = validated_data["username"]
            password = validated_data["password"]
            
            # Generar token de verificación
            verification_token = str(random.randint(100000, 999999))
            expires_at = timezone.now() + timedelta(hours=24)
            
            logger.info(f"Iniciando creación de usuario: {username}")
            
            with transaction.atomic():
                # Crear persona primero
                persona = Persona.objects.create(**persona_data)
                logger.debug(f"Persona creada con ID: {persona.id_persona}")
                
                # Crear usuario vinculado a la persona
                usuario = Usuario.objects.create_user(
                    username=username,
                    email=persona.email,
                    password=password,
                    persona=persona,
                    is_email_verified=False,
                    email_verification_token=verification_token,
                    email_verification_expires=expires_at,
                )
                logger.debug(f"Usuario creado con ID: {usuario.id}")
            
            # Enviar correo de verificación fuera de la transacción
            email_sent = EmailService.send_verification_email(usuario)
            
            if not email_sent:
                logger.warning(
                    f"Usuario {username} creado pero falló el envío de correo de verificación"
                )
            else:
                logger.info(f"Usuario {username} registrado exitosamente con correo enviado")
            
            return usuario
            
        except Exception as e:
            logger.error(f"Error creando usuario {validated_data.get('username', 'unknown')}: {e}")
            raise serializers.ValidationError(
                "Error interno durante el registro. Por favor, intenta nuevamente."
            )

class LoginSerializer(serializers.Serializer):
    """
    Serializer para autenticación de usuarios
    Incluye validaciones de seguridad y manejo de estados de cuenta
    """
    
    username = serializers.CharField(
        max_length=150,
        help_text="Nombre de usuario registrado"
    )
    password = serializers.CharField(
        write_only=True,
        help_text="Contraseña del usuario"
    )
    
    def validate_username(self, value: str) -> str:
        """Validar y sanitizar username"""
        value = bleach.clean(value, tags=[], strip=True).strip()
        
        if not value:
            raise serializers.ValidationError("El nombre de usuario es requerido.")
        
        return value.lower()  # Normalizar para búsqueda
    
    def validate_password(self, value: str) -> str:
        """Validación básica de contraseña en login"""
        if not value:
            raise serializers.ValidationError("La contraseña es requerida.")
        
        # No validar complejidad en login, solo en registro
        return value
    
    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validación completa de credenciales y estado de cuenta"""
        try:
            username = data.get("username")
            password = data.get("password")
            
            if not username or not password:
                raise serializers.ValidationError(
                    "Se requieren tanto username como contraseña."
                )
            
            # Buscar usuario con optimización
            try:
                usuario = Usuario.objects.select_related('persona').get(
                    username__iexact=username
                )
            except Usuario.DoesNotExist:
                logger.warning(f"Intento de login con usuario inexistente: {username}")
                raise serializers.ValidationError(ValidationMessages.USER_NOT_FOUND)
            
            # Verificar contraseña
            if not usuario.check_password(password):
                logger.warning(f"Intento de login con contraseña incorrecta para: {username}")
                raise serializers.ValidationError(ValidationMessages.INCORRECT_PASSWORD)
            
            # Verificar que la cuenta esté activa
            if not usuario.is_active:
                logger.warning(f"Intento de login con cuenta inactiva: {username}")
                raise serializers.ValidationError(
                    "Tu cuenta está desactivada. Contacta al administrador."
                )
            
            # Verificar verificación de email
            if not usuario.is_email_verified:
                logger.info(f"Intento de login sin verificación de email: {username}")
                raise serializers.ValidationError({
                    "email_not_verified": True,
                    "message": ValidationMessages.EMAIL_NOT_VERIFIED,
                    "details": {
                        "email": usuario.email,
                        "action": "Revisa tu bandeja de entrada o solicita un nuevo código",
                        "verification_endpoint": "/api/usuarios/verificar-email/",
                        "resend_endpoint": "/api/usuarios/reenviar-verificacion/"
                    }
                })
            
            # Agregar información del usuario a los datos validados
            data["usuario"] = usuario
            
            logger.debug(f"Validación de login exitosa para: {username}")
            return data
            
        except serializers.ValidationError:
            raise
        except Exception as e:
            logger.error(f"Error inesperado en validación de login: {e}")
            raise serializers.ValidationError(
                "Error interno de autenticación. Intenta nuevamente."
            )

class AuditoriaEventoSerializer(serializers.ModelSerializer):
    """
    Serializer para eventos de auditoría del sistema
    Incluye sanitización de datos y campos calculados
    """
    
    # Campos de solo lectura calculados
    tiempo_transcurrido = serializers.SerializerMethodField(
        help_text="Tiempo transcurrido desde el evento"
    )
    usuario_info = serializers.SerializerMethodField(
        help_text="Información básica del usuario relacionado"
    )
    
    class Meta:
        model = AuditoriaEvento
        fields = '__all__'
        read_only_fields = [
            'id', 'fecha', 'tiempo_transcurrido', 'usuario_info'
        ]
        extra_kwargs = {
            'detalle': {
                'help_text': 'Detalles adicionales del evento de auditoría'
            },
            'ip': {
                'help_text': 'Dirección IP desde donde se realizó la acción'
            },
            'user_agent': {
                'help_text': 'Información del navegador/cliente utilizado'
            }
        }
    
    def get_tiempo_transcurrido(self, obj: AuditoriaEvento) -> str:
        """Calcular tiempo transcurrido desde el evento"""
        try:
            if not obj.fecha:
                return "Desconocido"
            
            tiempo_delta = timezone.now() - obj.fecha
            
            if tiempo_delta.days > 0:
                return f"Hace {tiempo_delta.days} día{'s' if tiempo_delta.days != 1 else ''}"
            elif tiempo_delta.seconds > 3600:
                horas = tiempo_delta.seconds // 3600
                return f"Hace {horas} hora{'s' if horas != 1 else ''}"
            elif tiempo_delta.seconds > 60:
                minutos = tiempo_delta.seconds // 60
                return f"Hace {minutos} minuto{'s' if minutos != 1 else ''}"
            else:
                return "Hace menos de un minuto"
                
        except Exception as e:
            logger.error(f"Error calculando tiempo transcurrido: {e}")
            return "Error calculando tiempo"
    
    def get_usuario_info(self, obj: AuditoriaEvento) -> Optional[Dict[str, Any]]:
        """Obtener información básica del usuario"""
        try:
            if not obj.usuario:
                return None
            
            return {
                'id': obj.usuario.id,
                'username': obj.usuario.username,
                'email': obj.usuario.email,
                'nombre_completo': f"{obj.usuario.persona.nombre} {obj.usuario.persona.apellido}" if hasattr(obj.usuario, 'persona') else None
            }
        except Exception as e:
            logger.error(f"Error obteniendo info de usuario en auditoría: {e}")
            return None
    
    def validate_detalle(self, value: str) -> str:
        """Validar y sanitizar campo detalle"""
        if not value:
            return value
        
        # Sanitizar HTML/scripts maliciosos
        value = bleach.clean(
            value, 
            tags=[], 
            attributes={}, 
            strip=True
        )
        
        # Limitar longitud para evitar ataques de almacenamiento
        if len(value) > 1000:
            value = value[:997] + "..."
        
        return value.strip()
    
    def validate_user_agent(self, value: str) -> str:
        """Validar y sanitizar user agent"""
        if not value:
            return value
        
        # Sanitizar
        value = bleach.clean(value, tags=[], strip=True)
        
        # Limitar longitud
        if len(value) > 500:
            value = value[:497] + "..."
        
        return value.strip()
    
    def validate_ip(self, value: str) -> str:
        """Validar formato de IP"""
        if not value:
            return value
        
        # Sanitizar
        value = bleach.clean(value, tags=[], strip=True).strip()
        
        # Validación básica de formato IP (IPv4 o IPv6)
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            # Si no es una IP válida, aún permitir (puede ser proxy/load balancer)
            logger.warning(f"IP con formato no estándar en auditoría: {value}")
            return value

# ============================================================================
# DOCUMENTACIÓN Y NOTAS FINALES
# ============================================================================

"""
MEJORAS IMPLEMENTADAS EN SERIALIZERS:

1. ESTRUCTURA Y ORGANIZACIÓN:
   - Imports organizados por categorías
   - Constantes centralizadas en clases
   - Documentación completa de cada serializer

2. VALIDACIONES MEJORADAS:
   - Sanitización con bleach para prevenir XSS
   - Validaciones de formato más robustas
   - Mensajes de error centralizados y consistentes
   - Validaciones cruzadas optimizadas

3. RENDIMIENTO:
   - Patrones regex precompilados
   - Consultas optimizadas con select_related
   - frozenset para búsquedas rápidas en contraseñas comunes
   - Transacciones atómicas para operaciones críticas

4. SEGURIDAD:
   - Validador de contraseñas robusto con múltiples criterios
   - Sanitización de todos los campos de entrada
   - Validaciones de unicidad optimizadas
   - Logging de eventos de seguridad

5. EXPERIENCIA DE USUARIO:
   - Mensajes de error más informativos
   - Campos con help_text descriptivo
   - Validaciones tempranas para mejor UX
   - Normalización automática de datos

6. MANTENIBILIDAD:
   - Código modular con clases de utilidad
   - Logging estructurado para debugging
   - Tipo hints para mejor IDE support
   - Separación clara de responsabilidades

PRÓXIMOS PASOS RECOMENDADOS:
- Implementar cache para validaciones de unicidad
- Agregar rate limiting en validaciones costosas
- Implementar notificaciones push para eventos críticos
- Añadir métricas de performance en validaciones
"""
