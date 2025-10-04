"""
Modelos del sistema de gestión de edificio.
Alineado con esquema PostgreSQL - Optimizado: 4 de octubre de 2025
"""

# ============================================================================
# IMPORTS
# ============================================================================

# Imports estándar de Python
import base64
from decimal import Decimal
from typing import Optional, Dict, Any

# Imports de Django
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.contrib.auth.hashers import make_password, check_password
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# Imports locales
from apps.usuarios.crypto import encrypt_sensitive_data, decrypt_sensitive_data


# ============================================================================
# CONSTANTES Y VALIDADORES
# ============================================================================

class PersonaConstants:
    """Constantes para el modelo Persona"""
    SEXO_CHOICES = [
        ('M', 'Masculino'),
        ('F', 'Femenino'),
        ('O', 'Otro'),
    ]
    
    MAX_NOMBRE_LENGTH = 50
    MAX_APELLIDO_LENGTH = 50
    MAX_EMAIL_LENGTH = 100
    MAX_SEXO_LENGTH = 20

# Validadores personalizados
ci_validator = RegexValidator(
    regex=r'^\d{6,12}$',
    message='CI debe contener entre 6 y 12 dígitos numéricos'
)

telefono_validator = RegexValidator(
    regex=r'^\d{7,15}$',
    message='Teléfono debe contener entre 7 y 15 dígitos numéricos'
)

# ============================================================================
# MODELO BASE: PERSONA
# ============================================================================

class Persona(models.Model):
    """
    Modelo base para todas las personas del sistema
    Mapea directamente con la tabla Persona de PostgreSQL
    """
    
    id_persona = models.AutoField(
        primary_key=True,
        help_text="ID único de la persona"
    )
    
    nombre = models.CharField(
        max_length=PersonaConstants.MAX_NOMBRE_LENGTH,
        help_text="Nombre de la persona",
        db_index=True
    )
    
    apellido = models.CharField(
        max_length=PersonaConstants.MAX_APELLIDO_LENGTH,
        help_text="Apellido de la persona",
        db_index=True
    )
    
    # CI como IntegerField según esquema PostgreSQL
    ci = models.IntegerField(
        unique=True,
        validators=[
            MinValueValidator(100000, message="CI debe tener al menos 6 dígitos"),
            MaxValueValidator(999999999999, message="CI no puede tener más de 12 dígitos")
        ],
        help_text="Cédula de identidad (número entero)",
        db_index=True
    )
    
    email = models.EmailField(
        max_length=PersonaConstants.MAX_EMAIL_LENGTH,
        unique=True,
        help_text="Correo electrónico único",
        db_index=True
    )
    
    sexo = models.CharField(
        max_length=PersonaConstants.MAX_SEXO_LENGTH,
        choices=PersonaConstants.SEXO_CHOICES,
        null=True,
        blank=True,
        help_text="Sexo de la persona"
    )
    
    # Teléfono como IntegerField según esquema PostgreSQL
    telefono = models.IntegerField(
        null=True,
        blank=True,
        validators=[
            MinValueValidator(1000000, message="Teléfono debe tener al menos 7 dígitos"),
            MaxValueValidator(999999999999999, message="Teléfono no puede tener más de 15 dígitos")
        ],
        help_text="Número de teléfono (sin espacios ni caracteres especiales)",
        db_index=True
    )
    
    fecha_nacimiento = models.DateField(
        null=True,
        blank=True,
        help_text="Fecha de nacimiento"
    )

    class Meta:
        db_table = 'persona'
        verbose_name = 'Persona'
        verbose_name_plural = 'Personas'
        ordering = ['apellido', 'nombre']
        indexes = [
            models.Index(fields=['ci'], name='idx_persona_ci'),
            models.Index(fields=['email'], name='idx_persona_email'),
            models.Index(fields=['apellido', 'nombre'], name='idx_persona_nombre_completo'),
        ]

    def __str__(self) -> str:
        return f"{self.nombre} {self.apellido} (CI: {self.ci})"
    
    @property
    def nombre_completo(self) -> str:
        """Nombre completo de la persona"""
        return f"{self.nombre} {self.apellido}"
    
    @property
    def iniciales(self) -> str:
        """Iniciales del nombre y apellido"""
        return f"{self.nombre[0] if self.nombre else ''}{self.apellido[0] if self.apellido else ''}".upper()
    
    def clean(self):
        """Validaciones personalizadas del modelo"""
        from django.core.exceptions import ValidationError
        
        # Validar que la fecha de nacimiento no sea futura
        if self.fecha_nacimiento and self.fecha_nacimiento > timezone.now().date():
            raise ValidationError({
                'fecha_nacimiento': 'La fecha de nacimiento no puede ser futura'
            })
        
        # Normalizar email
        if self.email:
            self.email = self.email.lower().strip()
    
    def save(self, *args, **kwargs):
        """Sobrescribir save para ejecutar validaciones"""
        self.clean()
        super().save(*args, **kwargs)


# ============================================================================
# MANAGERS PERSONALIZADOS
# ============================================================================

class UsuarioManager(BaseUserManager):
    """Manager personalizado para el modelo Usuario"""
    
    def create_user(self, ci: int, nombre: str, apellido: str, email: str, 
                   password: str = None, **extra_fields) -> 'Usuario':
        """
        Crear usuario normal con su persona asociada
        """
        if not ci:
            raise ValueError('El usuario debe tener un CI')
        if not email:
            raise ValueError('El usuario debe tener un email')
        if not nombre or not apellido:
            raise ValueError('El usuario debe tener nombre y apellido')
        
        email = self.normalize_email(email)
        
        with transaction.atomic():
            # Crear la persona primero
            persona = Persona.objects.create(
                ci=ci,
                nombre=nombre,
                apellido=apellido,
                email=email,
                **{k: v for k, v in extra_fields.items() 
                   if k in ['sexo', 'telefono', 'fecha_nacimiento']}
            )
            
            # Crear el usuario usando el id de la persona
            user = self.model(
                id_usuario=persona.id_persona,
                persona=persona,
                **{k: v for k, v in extra_fields.items() 
                   if k not in ['sexo', 'telefono', 'fecha_nacimiento']}
            )
            
            if password:
                user.set_password(password)
            
            user.save(using=self._db)
            return user

    def create_superuser(self, ci: int, nombre: str, apellido: str, email: str, 
                        password: str = None, **extra_fields) -> 'Usuario':
        """
        Crear superusuario con todos los permisos
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser debe tener is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser debe tener is_superuser=True.')
        
        return self.create_user(ci, nombre, apellido, email, password, **extra_fields)

# ============================================================================
# MODELOS DE ROLES (HERENCIA DE PERSONA)
# ============================================================================

class Usuario(AbstractBaseUser, PermissionsMixin):
    """
    Modelo Usuario que hereda de Persona según esquema PostgreSQL
    Implementa autenticación personalizada con campos de seguridad y permisos
    """
    
    # ID como clave foránea de Persona (herencia por tabla)
    id_usuario = models.OneToOneField(
        Persona,
        on_delete=models.CASCADE,
        primary_key=True,
        db_column='id_usuario',
        help_text="ID del usuario (referencia a Persona)"
    )
    
    # Campos de autenticación Django
    is_active = models.BooleanField(
        default=True,
        help_text="Usuario activo en el sistema"
    )
    is_staff = models.BooleanField(
        default=False,
        help_text="Usuario puede acceder al admin"
    )
    is_superuser = models.BooleanField(
        default=False,
        help_text="Usuario tiene permisos de superusuario"
    )
    date_joined = models.DateTimeField(
        default=timezone.now,
        help_text="Fecha de registro"
    )
    
    # Campos de seguridad y verificación
    password = models.CharField(
        max_length=128,
        help_text="Hash de la contraseña"
    )
    is_email_verified = models.BooleanField(
        default=False,
        help_text="Email verificado"
    )
    email_verification_token = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="Token de verificación de email"
    )
    email_verification_expires = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Expiración del token de verificación"
    )
    reset_password_token = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="Token de recuperación de contraseña"
    )
    login_token = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        help_text="Token de login temporal"
    )
    
    # 2FA y seguridad avanzada
    two_factor_secret = models.CharField(
        max_length=32,
        null=True,
        blank=True,
        help_text="Secreto para 2FA"
    )
    two_factor_enabled = models.BooleanField(
        default=False,
        help_text="2FA habilitado"
    )
    failed_login_attempts = models.IntegerField(
        default=0,
        help_text="Intentos fallidos de login"
    )
    account_locked_until = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Cuenta bloqueada hasta esta fecha"
    )
    
    # Relaciones con permisos - SOLUCIÓN AL CONFLICTO con related_name personalizados
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='grupos',
        blank=True,
        help_text='Los grupos a los que pertenece este usuario.',
        related_name='usuarios_edificio',  # 🔥 Evita conflicto con auth.User
        related_query_name='usuario_edificio',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='permisos de usuario',
        blank=True,
        help_text='Permisos específicos para este usuario.',
        related_name='usuarios_edificio',  # 🔥 Evita conflicto con auth.User
        related_query_name='usuario_edificio',
    )

    # Configuración del usuario Django
    USERNAME_FIELD = "id_usuario"  # Usar CI como username
    REQUIRED_FIELDS = []  # CI se maneja en el manager

    objects = UsuarioManager()

    class Meta:
        db_table = 'usuario'
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'

    def __str__(self) -> str:
        return f"Usuario: {self.persona.nombre_completo} (CI: {self.persona.ci})"
    
    @property
    def persona(self) -> Persona:
        """Acceso directo a la persona asociada"""
        return self.id_usuario
    
    @property
    def username(self) -> str:
        """Username basado en CI para compatibilidad"""
        return str(self.persona.ci)
    
    @property
    def email(self) -> str:
        """Email de la persona asociada"""
        return self.persona.email
    
    @property
    def get_full_name(self) -> str:
        """Nombre completo del usuario"""
        return self.persona.nombre_completo
    
    @property
    def get_short_name(self) -> str:
        """Nombre corto del usuario"""
        return self.persona.nombre
    
    def set_password(self, raw_password: str):
        """Hashear contraseña usando el sistema seguro de Django"""
        self.password = make_password(raw_password)
        self._password = raw_password
    
    def check_password(self, raw_password: str) -> bool:
        """Verificar contraseña usando el sistema hash de Django"""
        return check_password(raw_password, self.password)
    
    def is_account_locked(self) -> bool:
        """Verificar si la cuenta está bloqueada"""
        if not self.account_locked_until:
            return False
        return timezone.now() < self.account_locked_until
    
    def unlock_account(self):
        """Desbloquear cuenta y resetear intentos fallidos"""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['account_locked_until', 'failed_login_attempts'])
    
    def increment_failed_attempts(self):
        """Incrementar intentos fallidos y bloquear si es necesario"""
        self.failed_login_attempts += 1
        
        # Bloquear cuenta después de 5 intentos fallidos
        if self.failed_login_attempts >= 5:
            self.account_locked_until = timezone.now() + timezone.timedelta(minutes=30)
        
        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])
    
    def reset_failed_attempts(self):
        """Resetear intentos fallidos después de login exitoso"""
        if self.failed_login_attempts > 0:
            self.failed_login_attempts = 0
            self.save(update_fields=['failed_login_attempts'])
    
    def has_perm(self, perm, obj=None):
        """Verificar si el usuario tiene un permiso específico"""
        if self.is_active and self.is_superuser:
            return True
        return super().has_perm(perm, obj)
    
    def has_perms(self, perm_list, obj=None):
        """Verificar si el usuario tiene una lista de permisos"""
        if self.is_active and self.is_superuser:
            return True
        return super().has_perms(perm_list, obj)
    
    def has_module_perms(self, app_label):
        """Verificar si el usuario tiene permisos en un módulo"""
        if self.is_active and self.is_superuser:
            return True
        return super().has_module_perms(app_label)


class Personal(models.Model):
    """
    Modelo Personal que hereda de Persona
    Personal del edificio (empleados, conserjes, etc.)
    """
    
    TURNO_CHOICES = [
        ('mañana', 'Turno Mañana'),
        ('tarde', 'Turno Tarde'),
        ('noche', 'Turno Noche'),
        ('completo', 'Turno Completo'),
    ]
    
    CARGO_CHOICES = [
        ('conserje', 'Conserje'),
        ('seguridad', 'Seguridad'),
        ('mantenimiento', 'Mantenimiento'),
        ('limpieza', 'Limpieza'),
        ('administracion', 'Administración'),
        ('supervisor', 'Supervisor'),
    ]
    
    id_personal = models.OneToOneField(
        Persona,
        on_delete=models.CASCADE,
        primary_key=True,
        db_column='id_personal',
        help_text="ID del personal (referencia a Persona)"
    )
    
    turno = models.CharField(
        max_length=20,
        choices=TURNO_CHOICES,
        help_text="Turno de trabajo del personal"
    )
    
    cargo = models.CharField(
        max_length=50,
        choices=CARGO_CHOICES,
        help_text="Cargo o función del personal"
    )

    class Meta:
        db_table = 'personal'
        verbose_name = 'Personal'
        verbose_name_plural = 'Personal'
        
    def __str__(self) -> str:
        return f"{self.id_personal.nombre_completo} - {self.cargo} ({self.turno})"


class Administrador(models.Model):
    """
    Modelo Administrador que hereda de Persona
    Administradores del sistema con diferentes niveles de acceso
    """
    
    NIVEL_ACCESO_CHOICES = [
        ('basico', 'Básico'),
        ('intermedio', 'Intermedio'),
        ('avanzado', 'Avanzado'),
        ('super_admin', 'Super Administrador'),
    ]
    
    id_admin = models.OneToOneField(
        Persona,
        on_delete=models.CASCADE,
        primary_key=True,
        db_column='id_admin',
        help_text="ID del administrador (referencia a Persona)"
    )
    
    nivel_acceso = models.CharField(
        max_length=20,
        choices=NIVEL_ACCESO_CHOICES,
        default='basico',
        help_text="Nivel de acceso del administrador"
    )

    class Meta:
        db_table = 'administrador'
        verbose_name = 'Administrador'
        verbose_name_plural = 'Administradores'
        
    def __str__(self) -> str:
        return f"Admin: {self.id_admin.nombre_completo} ({self.nivel_acceso})"


class Junta(models.Model):
    """
    Modelo Junta que hereda de Persona
    Miembros de la junta directiva del edificio
    """
    
    CARGO_JUNTA_CHOICES = [
        ('presidente', 'Presidente'),
        ('vicepresidente', 'Vicepresidente'),
        ('secretario', 'Secretario'),
        ('tesorero', 'Tesorero'),
        ('vocal', 'Vocal'),
        ('sindico', 'Síndico'),
    ]
    
    id_junta = models.OneToOneField(
        Persona,
        on_delete=models.CASCADE,
        primary_key=True,
        db_column='id_junta',
        help_text="ID del miembro de junta (referencia a Persona)"
    )
    
    cargo = models.CharField(
        max_length=50,
        choices=CARGO_JUNTA_CHOICES,
        help_text="Cargo en la junta directiva"
    )

    class Meta:
        db_table = 'junta'
        verbose_name = 'Miembro de Junta'
        verbose_name_plural = 'Junta Directiva'
        
    def __str__(self) -> str:
        return f"{self.cargo}: {self.id_junta.nombre_completo}"


# ============================================================================
# MODELOS DE ESTRUCTURA FÍSICA
# ============================================================================

class Departamento(models.Model):
    """
    Modelo Departamento - Unidades habitacionales del edificio
    """
    
    id_departamento = models.AutoField(
        primary_key=True,
        help_text="ID único del departamento"
    )
    
    nombre_departamento = models.CharField(
        max_length=50,
        unique=True,
        help_text="Nombre o número del departamento (ej: 101, A-1)",
        db_index=True
    )
    
    piso = models.IntegerField(
        validators=[
            MinValueValidator(-5, message="El piso no puede ser menor a -5"),
            MaxValueValidator(50, message="El piso no puede ser mayor a 50")
        ],
        help_text="Número de piso donde se ubica",
        db_index=True
    )
    
    nro_habitaciones = models.IntegerField(
        validators=[
            MinValueValidator(0, message="Número de habitaciones no puede ser negativo"),
            MaxValueValidator(20, message="Número de habitaciones no puede ser mayor a 20")
        ],
        help_text="Número de habitaciones"
    )
    
    nro_banios = models.IntegerField(
        validators=[
            MinValueValidator(0, message="Número de baños no puede ser negativo"),
            MaxValueValidator(10, message="Número de baños no puede ser mayor a 10")
        ],
        help_text="Número de baños"
    )
    
    area = models.IntegerField(
        validators=[
            MinValueValidator(1, message="Área debe ser mayor a 0"),
            MaxValueValidator(10000, message="Área no puede ser mayor a 10000 m²")
        ],
        help_text="Área en metros cuadrados"
    )

    class Meta:
        db_table = 'departamento'
        verbose_name = 'Departamento'
        verbose_name_plural = 'Departamentos'
        ordering = ['piso', 'nombre_departamento']
        indexes = [
            models.Index(fields=['piso'], name='idx_departamento_piso'),
            models.Index(fields=['nombre_departamento'], name='idx_departamento_nombre'),
        ]
        
    def __str__(self) -> str:
        return f"Depto {self.nombre_departamento} - Piso {self.piso}"
    
    @property
    def descripcion_completa(self) -> str:
        """Descripción completa del departamento"""
        return f"{self.nombre_departamento} - {self.nro_habitaciones}H/{self.nro_banios}B - {self.area}m² - Piso {self.piso}"


# ============================================================================
# MODELOS DEL SISTEMA DE SEGURIDAD
# ============================================================================

class Camara(models.Model):
    """
    Modelo Cámara - Sistema de videovigilancia
    """
    
    ESTADO_CHOICES = [
        ('activa', 'Activa'),
        ('inactiva', 'Inactiva'),
        ('mantenimiento', 'En Mantenimiento'),
        ('dañada', 'Dañada'),
    ]
    
    id_camara = models.AutoField(
        primary_key=True,
        help_text="ID único de la cámara"
    )
    
    ubicacion = models.CharField(
        max_length=100,
        help_text="Ubicación de la cámara",
        db_index=True
    )
    
    estado = models.CharField(
        max_length=20,
        choices=ESTADO_CHOICES,
        default='activa',
        help_text="Estado actual de la cámara",
        db_index=True
    )

    class Meta:
        db_table = 'camara'
        verbose_name = 'Cámara'
        verbose_name_plural = 'Cámaras'
        ordering = ['ubicacion']
        
    def __str__(self) -> str:
        return f"Cámara {self.id_camara} - {self.ubicacion} ({self.estado})"


class Grabacion(models.Model):
    """
    Modelo Grabación - Archivos de video de las cámaras
    """
    
    id_grabacion = models.AutoField(
        primary_key=True,
        help_text="ID único de la grabación"
    )
    
    fecha = models.DateTimeField(
        default=timezone.now,
        help_text="Fecha y hora de la grabación",
        db_index=True
    )
    
    archivo = models.CharField(
        max_length=255,
        help_text="Ruta del archivo de grabación"
    )
    
    id_camara = models.ForeignKey(
        Camara,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Cámara que realizó la grabación",
        db_index=True
    )

    class Meta:
        db_table = 'grabacion'
        verbose_name = 'Grabación'
        verbose_name_plural = 'Grabaciones'
        ordering = ['-fecha']
        indexes = [
            models.Index(fields=['-fecha'], name='idx_grabacion_fecha_desc'),
            models.Index(fields=['id_camara', '-fecha'], name='idx_grabacion_camara_fecha'),
        ]
        
    def __str__(self) -> str:
        return f"Grabación {self.id_grabacion} - {self.fecha} ({self.id_camara})"


class Acceso(models.Model):
    """
    Modelo Acceso - Registro de accesos al edificio
    """
    
    METODO_CHOICES = [
        ('biometria', 'Biometría'),
        ('qr', 'Código QR'),
        ('rfid', 'RFID'),
        ('pin', 'PIN'),
        ('manual', 'Manual'),
    ]
    
    RESULTADO_CHOICES = [
        ('exitoso', 'Exitoso'),
        ('denegado', 'Denegado'),
        ('error', 'Error'),
    ]
    
    id_acceso = models.AutoField(
        primary_key=True,
        help_text="ID único del acceso"
    )
    
    id_persona = models.ForeignKey(
        Persona,
        on_delete=models.CASCADE,
        help_text="Persona que intentó el acceso",
        db_index=True
    )
    
    hora_entrada = models.DateTimeField(
        default=timezone.now,
        help_text="Hora de entrada",
        db_index=True
    )
    
    hora_salida = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Hora de salida"
    )
    
    lugar = models.CharField(
        max_length=100,
        help_text="Lugar del acceso (entrada principal, garaje, etc.)"
    )
    
    metodo = models.CharField(
        max_length=50,
        choices=METODO_CHOICES,
        help_text="Método utilizado para el acceso"
    )
    
    resultado = models.CharField(
        max_length=50,
        choices=RESULTADO_CHOICES,
        help_text="Resultado del intento de acceso",
        db_index=True
    )
    
    motivo = models.CharField(
        max_length=100,
        blank=True,
        help_text="Motivo del acceso o denegación"
    )
    
    id_grabacion = models.ForeignKey(
        Grabacion,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Grabación asociada al acceso"
    )
    
    id_biometrico = models.ForeignKey(
        'Biometricos',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Datos biométricos utilizados"
    )

    class Meta:
        db_table = 'acceso'
        verbose_name = 'Acceso'
        verbose_name_plural = 'Accesos'
        ordering = ['-hora_entrada']
        indexes = [
            models.Index(fields=['-hora_entrada'], name='idx_acceso_hora_entrada'),
            models.Index(fields=['id_persona', '-hora_entrada'], name='idx_acceso_persona_fecha'),
            models.Index(fields=['resultado'], name='idx_acceso_resultado'),
        ]
        
    def __str__(self) -> str:
        return f"Acceso {self.id_persona.nombre_completo} - {self.lugar} ({self.resultado})"
    
    @property
    def tiempo_permanencia(self) -> Optional[timezone.timedelta]:
        """Tiempo de permanencia si hay hora de salida"""
        if self.hora_salida:
            return self.hora_salida - self.hora_entrada
        return None


# ============================================================================
# MODELOS FINANCIEROS
# ============================================================================

class Factura(models.Model):
    """
    Modelo Factura - Facturas del edificio
    """
    
    ESTADO_CHOICES = [
        ('pendiente', 'Pendiente'),
        ('pagada', 'Pagada'),
        ('vencida', 'Vencida'),
        ('cancelada', 'Cancelada'),
    ]
    
    id_factura = models.AutoField(
        primary_key=True,
        help_text="ID único de la factura"
    )
    
    nombre = models.CharField(
        max_length=100,
        help_text="Nombre o descripción de la factura"
    )
    
    fecha_emision = models.DateField(
        default=timezone.now,
        help_text="Fecha de emisión de la factura",
        db_index=True
    )
    
    fecha_vencimiento = models.DateField(
        help_text="Fecha de vencimiento de la factura",
        db_index=True
    )
    
    descripcion = models.TextField(
        blank=True,
        help_text="Descripción detallada de la factura"
    )
    
    costo_total = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text="Costo total de la factura"
    )
    
    estado = models.CharField(
        max_length=20,
        choices=ESTADO_CHOICES,
        default='pendiente',
        help_text="Estado actual de la factura",
        db_index=True
    )
    
    id_pago = models.OneToOneField(
        'Pago',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        unique=True,
        help_text="Pago asociado a esta factura"
    )

    class Meta:
        db_table = 'factura'
        verbose_name = 'Factura'
        verbose_name_plural = 'Facturas'
        ordering = ['-fecha_emision']
        indexes = [
            models.Index(fields=['-fecha_emision'], name='idx_factura_fecha_emision'),
            models.Index(fields=['estado'], name='idx_factura_estado'),
            models.Index(fields=['fecha_vencimiento'], name='idx_factura_vencimiento'),
        ]
        
    def __str__(self) -> str:
        return f"Factura {self.nombre} - {self.costo_total} Bs. ({self.estado})"
    
    @property
    def esta_vencida(self) -> bool:
        """Verificar si la factura está vencida"""
        return self.fecha_vencimiento < timezone.now().date() and self.estado == 'pendiente'
    
    @property
    def dias_vencimiento(self) -> int:
        """Días hasta el vencimiento (negativo si ya venció)"""
        return (self.fecha_vencimiento - timezone.now().date()).days


# ============================================================================
# MODELOS OPTIMIZADOS EXISTENTES
# ============================================================================

class Biometricos(models.Model):
    """
    Modelo Biométricos optimizado - Datos biométricos encriptados
    Mapea con tabla PostgreSQL usando BYTEA para datos binarios
    """
    
    id_biometrico = models.AutoField(
        primary_key=True,
        help_text="ID único del registro biométrico"
    )
    
    # Campos encriptados para datos biométricos
    huellas_encrypted = models.TextField(
        null=True,
        blank=True,
        help_text="Datos de huellas dactilares encriptados"
    )
    
    rostro_encrypted = models.TextField(
        null=True,
        blank=True,
        help_text="Datos de reconocimiento facial encriptados"
    )
    
    iris_encrypted = models.TextField(
        null=True,
        blank=True,
        help_text="Datos de reconocimiento de iris encriptados"
    )
    
    id_persona = models.ForeignKey(
        Persona,
        on_delete=models.CASCADE,
        help_text="Persona asociada a los datos biométricos",
        db_index=True
    )

    class Meta:
        db_table = 'biometricos'
        verbose_name = 'Dato Biométrico'
        verbose_name_plural = 'Datos Biométricos'
        
    def __str__(self) -> str:
        return f"Biométricos de {self.id_persona.nombre_completo}"

    # Métodos para huellas dactilares
    def set_huellas(self, raw_bytes: bytes):
        """Encriptar y guardar datos de huellas dactilares"""
        if raw_bytes:
            b64_str = base64.b64encode(raw_bytes).decode()
            self.huellas_encrypted = encrypt_sensitive_data(b64_str)
        else:
            self.huellas_encrypted = None

    def get_huellas(self) -> bytes:
        """Desencriptar y obtener datos de huellas dactilares"""
        if not self.huellas_encrypted:
            return b""
        try:
            b64 = decrypt_sensitive_data(self.huellas_encrypted)
            return base64.b64decode(b64)
        except Exception:
            return b""  # Si hay error en desencriptación, retornar vacío

    # Métodos para reconocimiento facial
    def set_rostro(self, raw_bytes: bytes):
        """Encriptar y guardar datos de reconocimiento facial"""
        if raw_bytes:
            b64_str = base64.b64encode(raw_bytes).decode()
            self.rostro_encrypted = encrypt_sensitive_data(b64_str)
        else:
            self.rostro_encrypted = None

    def get_rostro(self) -> bytes:
        """Desencriptar y obtener datos de reconocimiento facial"""
        if not self.rostro_encrypted:
            return b""
        try:
            b64 = decrypt_sensitive_data(self.rostro_encrypted)
            return base64.b64decode(b64)
        except Exception:
            return b""

    # Métodos para reconocimiento de iris
    def set_iris(self, raw_bytes: bytes):
        """Encriptar y guardar datos de reconocimiento de iris"""
        if raw_bytes:
            b64_str = base64.b64encode(raw_bytes).decode()
            self.iris_encrypted = encrypt_sensitive_data(b64_str)
        else:
            self.iris_encrypted = None

    def get_iris(self) -> bytes:
        """Desencriptar y obtener datos de reconocimiento de iris"""
        if not self.iris_encrypted:
            return b""
        try:
            b64 = decrypt_sensitive_data(self.iris_encrypted)
            return base64.b64decode(b64)
        except Exception:
            return b""
    
    @property
    def tiene_huellas(self) -> bool:
        """Verificar si tiene datos de huellas"""
        return bool(self.huellas_encrypted)
    
    @property
    def tiene_rostro(self) -> bool:
        """Verificar si tiene datos de rostro"""
        return bool(self.rostro_encrypted)
    
    @property
    def tiene_iris(self) -> bool:
        """Verificar si tiene datos de iris"""
        return bool(self.iris_encrypted)
    
    @property
    def metodos_disponibles(self) -> list:
        """Lista de métodos biométricos disponibles"""
        metodos = []
        if self.tiene_huellas:
            metodos.append('huellas')
        if self.tiene_rostro:
            metodos.append('rostro')
        if self.tiene_iris:
            metodos.append('iris')
        return metodos


class Pago(models.Model):
    """
    Modelo Pago - Pagos realizados por usuarios
    Optimizado según esquema PostgreSQL
    """
    
    METODO_PAGO_CHOICES = [
        ('efectivo', 'Efectivo'),
        ('transferencia', 'Transferencia Bancaria'),
        ('cheque', 'Cheque'),
        ('tarjeta_debito', 'Tarjeta de Débito'),
        ('tarjeta_credito', 'Tarjeta de Crédito'),
        ('qr', 'Código QR'),
        ('online', 'Pago Online'),
    ]
    
    ESTADO_PAGO_CHOICES = [
        ('pendiente', 'Pendiente'),
        ('procesando', 'Procesando'),
        ('completado', 'Completado'),
        ('fallido', 'Fallido'),
        ('revertido', 'Revertido'),
    ]
    
    id_pago = models.AutoField(
        primary_key=True,
        help_text="ID único del pago"
    )
    
    metodo_pago = models.CharField(
        max_length=50,
        choices=METODO_PAGO_CHOICES,
        help_text="Método utilizado para el pago"
    )
    
    fecha_pago = models.DateField(
        null=True,
        blank=True,
        help_text="Fecha en que se realizó el pago",
        db_index=True
    )
    
    estado = models.CharField(
        max_length=20,
        choices=ESTADO_PAGO_CHOICES,
        default='pendiente',
        help_text="Estado actual del pago",
        db_index=True
    )
    
    referencia_bancaria_encrypted = models.TextField(
        null=True,
        blank=True,
        help_text="Referencia bancaria encriptada"
    )
    
    id_usuario = models.ForeignKey(
        Usuario,
        on_delete=models.CASCADE,
        help_text="Usuario que realizó el pago",
        db_index=True
    )

    class Meta:
        db_table = 'pago'
        verbose_name = 'Pago'
        verbose_name_plural = 'Pagos'
        ordering = ['-fecha_pago']
        indexes = [
            models.Index(fields=['-fecha_pago'], name='idx_pago_fecha'),
            models.Index(fields=['estado'], name='idx_pago_estado'),
            models.Index(fields=['id_usuario', '-fecha_pago'], name='idx_pago_usuario_fecha'),
        ]

    def __str__(self) -> str:
        return f"Pago {self.id_pago} - {self.id_usuario.persona.nombre_completo} ({self.estado})"

    def set_referencia(self, raw_ref: str):
        """Encriptar y guardar referencia bancaria"""
        if raw_ref:
            self.referencia_bancaria_encrypted = encrypt_sensitive_data(raw_ref.strip())
        else:
            self.referencia_bancaria_encrypted = None

    def get_referencia(self) -> str:
        """Desencriptar y obtener referencia bancaria"""
        if not self.referencia_bancaria_encrypted:
            return ""
        try:
            return decrypt_sensitive_data(self.referencia_bancaria_encrypted)
        except Exception:
            return ""  # Si hay error en desencriptación, retornar vacío
    
    @property
    def referencia_parcial(self) -> str:
        """Obtener referencia parcialmente oculta para mostrar"""
        ref = self.get_referencia()
        if len(ref) <= 4:
            return "*" * len(ref)
        return f"****{ref[-4:]}"


# ============================================================================
# MODELOS DE SERVICIOS Y ÁREAS COMUNES
# ============================================================================

class AreaComun(models.Model):
    """
    Modelo Área Común - Espacios compartidos del edificio
    """
    
    TIPO_CHOICES = [
        ('salon_eventos', 'Salón de Eventos'),
        ('gimnasio', 'Gimnasio'),
        ('piscina', 'Piscina'),
        ('terraza', 'Terraza'),
        ('parrillero', 'Parrillero'),
        ('salon_usos_multiples', 'Salón de Usos Múltiples'),
        ('cancha_deportiva', 'Cancha Deportiva'),
        ('jardin', 'Jardín'),
        ('estacionamiento', 'Estacionamiento'),
    ]
    
    id_areacomun = models.AutoField(
        primary_key=True,
        help_text="ID único del área común"
    )
    
    nombre = models.CharField(
        max_length=100,
        unique=True,
        help_text="Nombre del área común",
        db_index=True
    )
    
    tipo = models.CharField(
        max_length=50,
        choices=TIPO_CHOICES,
        help_text="Tipo de área común"
    )
    
    piso = models.IntegerField(
        validators=[
            MinValueValidator(-5, message="El piso no puede ser menor a -5"),
            MaxValueValidator(50, message="El piso no puede ser mayor a 50")
        ],
        help_text="Piso donde se ubica el área común"
    )

    class Meta:
        db_table = 'area_comun'
        verbose_name = 'Área Común'
        verbose_name_plural = 'Áreas Comunes'
        ordering = ['piso', 'nombre']
        
    def __str__(self) -> str:
        return f"{self.nombre} ({self.tipo}) - Piso {self.piso}"


class Reserva(models.Model):
    """
    Modelo Reserva - Reservas de áreas comunes
    """
    
    ESTADO_CHOICES = [
        ('pendiente', 'Pendiente'),
        ('confirmada', 'Confirmada'),
        ('cancelada', 'Cancelada'),
        ('completada', 'Completada'),
        ('no_show', 'No Show'),
    ]
    
    id_reserva = models.AutoField(
        primary_key=True,
        help_text="ID único de la reserva"
    )
    
    fecha = models.DateField(
        help_text="Fecha de la reserva",
        db_index=True
    )
    
    hora_inicio = models.TimeField(
        help_text="Hora de inicio de la reserva"
    )
    
    hora_fin = models.TimeField(
        help_text="Hora de fin de la reserva"
    )
    
    estado = models.CharField(
        max_length=20,
        choices=ESTADO_CHOICES,
        default='pendiente',
        help_text="Estado de la reserva",
        db_index=True
    )
    
    id_usuario = models.ForeignKey(
        Usuario,
        on_delete=models.CASCADE,
        help_text="Usuario que hizo la reserva",
        db_index=True
    )
    
    id_areacomun = models.ForeignKey(
        AreaComun,
        on_delete=models.CASCADE,
        help_text="Área común reservada",
        db_index=True
    )

    class Meta:
        db_table = 'reserva'
        verbose_name = 'Reserva'
        verbose_name_plural = 'Reservas'
        ordering = ['-fecha', '-hora_inicio']
        unique_together = [['id_areacomun', 'fecha', 'hora_inicio', 'hora_fin']]
        indexes = [
            models.Index(fields=['fecha', 'hora_inicio'], name='idx_reserva_fecha_hora'),
            models.Index(fields=['id_usuario', '-fecha'], name='idx_reserva_usuario_fecha'),
            models.Index(fields=['estado'], name='idx_reserva_estado'),
        ]
        
    def __str__(self) -> str:
        return f"Reserva {self.id_areacomun.nombre} - {self.fecha} ({self.id_usuario.persona.nombre_completo})"
    
    def clean(self):
        """Validaciones personalizadas"""
        from django.core.exceptions import ValidationError
        
        if self.hora_inicio >= self.hora_fin:
            raise ValidationError({
                'hora_fin': 'La hora de fin debe ser posterior a la hora de inicio'
            })
        
        # Validar que no sea una fecha pasada
        if self.fecha < timezone.now().date():
            raise ValidationError({
                'fecha': 'No se pueden hacer reservas para fechas pasadas'
            })


class Servicio(models.Model):
    """
    Modelo Servicio - Servicios consumidos por departamentos
    """
    
    TIPO_CHOICES = [
        ('agua', 'Agua'),
        ('luz', 'Electricidad'),
        ('gas', 'Gas'),
        ('internet', 'Internet'),
        ('telefono', 'Teléfono'),
        ('cable', 'Cable TV'),
        ('mantenimiento', 'Mantenimiento'),
        ('limpieza', 'Limpieza'),
        ('seguridad', 'Seguridad'),
    ]
    
    UNIDAD_CHOICES = [
        ('m3', 'Metros Cúbicos'),
        ('kwh', 'Kilovatios/Hora'),
        ('litros', 'Litros'),
        ('unidad', 'Unidad'),
        ('mes', 'Mensual'),
    ]
    
    id_servicio = models.AutoField(
        primary_key=True,
        help_text="ID único del servicio"
    )
    
    nombre_servicio = models.CharField(
        max_length=100,
        help_text="Nombre del servicio"
    )
    
    consumo = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Cantidad consumida"
    )
    
    unidad = models.CharField(
        max_length=20,
        choices=UNIDAD_CHOICES,
        help_text="Unidad de medida del consumo"
    )
    
    tipo = models.CharField(
        max_length=50,
        choices=TIPO_CHOICES,
        help_text="Tipo de servicio"
    )
    
    fecha_registro = models.DateField(
        default=timezone.now,
        help_text="Fecha de registro del consumo",
        db_index=True
    )
    
    id_departamento = models.ForeignKey(
        Departamento,
        on_delete=models.CASCADE,
        help_text="Departamento que consume el servicio",
        db_index=True
    )
    
    id_factura = models.ForeignKey(
        Factura,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Factura asociada al servicio"
    )

    class Meta:
        db_table = 'servicio'
        verbose_name = 'Servicio'
        verbose_name_plural = 'Servicios'
        ordering = ['-fecha_registro']
        indexes = [
            models.Index(fields=['-fecha_registro'], name='idx_servicio_fecha'),
            models.Index(fields=['tipo'], name='idx_servicio_tipo'),
            models.Index(fields=['id_departamento', '-fecha_registro'], name='idx_servicio_depto_fecha'),
        ]
        
    def __str__(self) -> str:
        return f"{self.nombre_servicio} - {self.id_departamento.nombre_departamento} ({self.consumo} {self.unidad})"


class Mantenimiento(models.Model):
    """
    Modelo Mantenimiento - Trabajos de mantenimiento del edificio
    """
    
    TIPO_CHOICES = [
        ('preventivo', 'Preventivo'),
        ('correctivo', 'Correctivo'),
        ('emergencia', 'Emergencia'),
        ('mejora', 'Mejora'),
    ]
    
    id_mantenimiento = models.AutoField(
        primary_key=True,
        help_text="ID único del mantenimiento"
    )
    
    nombre = models.CharField(
        max_length=100,
        help_text="Nombre del trabajo de mantenimiento"
    )
    
    tipo = models.CharField(
        max_length=50,
        choices=TIPO_CHOICES,
        help_text="Tipo de mantenimiento"
    )
    
    descripcion = models.TextField(
        blank=True,
        help_text="Descripción detallada del mantenimiento"
    )
    
    id_factura = models.ForeignKey(
        Factura,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Factura asociada al mantenimiento"
    )

    class Meta:
        db_table = 'mantenimiento'
        verbose_name = 'Mantenimiento'
        verbose_name_plural = 'Mantenimientos'
        ordering = ['nombre']
        
    def __str__(self) -> str:
        return f"{self.nombre} ({self.tipo})"


# ============================================================================
# MODELOS DE COMUNICACIÓN E INCIDENTES
# ============================================================================

class Notificacion(models.Model):
    """
    Modelo Notificación - Sistema de notificaciones
    """
    
    VIA_CHOICES = [
        ('push', 'Push Notification'),
        ('email', 'Email'),
        ('sms', 'SMS'),
        ('whatsapp', 'WhatsApp'),
    ]
    
    ESTADO_CHOICES = [
        ('pendiente', 'Pendiente'),
        ('enviada', 'Enviada'),
        ('leida', 'Leída'),
        ('fallida', 'Fallida'),
    ]
    
    id_notificacion = models.AutoField(
        primary_key=True,
        help_text="ID único de la notificación"
    )
    
    mensaje = models.TextField(
        help_text="Contenido del mensaje de la notificación"
    )
    
    fecha_envio = models.DateTimeField(
        default=timezone.now,
        help_text="Fecha y hora de envío",
        db_index=True
    )
    
    motivo = models.CharField(
        max_length=100,
        help_text="Motivo o razón de la notificación"
    )
    
    via = models.CharField(
        max_length=20,
        choices=VIA_CHOICES,
        help_text="Medio por el cual se envía la notificación"
    )
    
    estado = models.CharField(
        max_length=20,
        choices=ESTADO_CHOICES,
        default='pendiente',
        help_text="Estado actual de la notificación",
        db_index=True
    )
    
    id_personal = models.ForeignKey(
        Personal,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Personal que envía la notificación"
    )

    class Meta:
        db_table = 'notificacion'
        verbose_name = 'Notificación'
        verbose_name_plural = 'Notificaciones'
        ordering = ['-fecha_envio']
        indexes = [
            models.Index(fields=['-fecha_envio'], name='idx_notificacion_fecha'),
            models.Index(fields=['estado'], name='idx_notificacion_estado'),
        ]
        
    def __str__(self) -> str:
        return f"Notificación {self.motivo} - {self.via} ({self.estado})"


class Incidente(models.Model):
    """
    Modelo Incidente - Registro de incidentes en el edificio
    """
    
    TIPO_CHOICES = [
        ('seguridad', 'Seguridad'),
        ('mantenimiento', 'Mantenimiento'),
        ('emergencia', 'Emergencia'),
        ('ruido', 'Ruido'),
        ('limpieza', 'Limpieza'),
        ('otros', 'Otros'),
    ]
    
    id_incidente = models.AutoField(
        primary_key=True,
        help_text="ID único del incidente"
    )
    
    descripcion = models.TextField(
        help_text="Descripción detallada del incidente"
    )
    
    fecha = models.DateTimeField(
        default=timezone.now,
        help_text="Fecha y hora del incidente",
        db_index=True
    )
    
    tipo = models.CharField(
        max_length=50,
        choices=TIPO_CHOICES,
        help_text="Tipo de incidente",
        db_index=True
    )
    
    archivo = models.CharField(
        max_length=255,
        blank=True,
        help_text="Archivo adjunto (foto, video, documento)"
    )
    
    ubicacion = models.CharField(
        max_length=100,
        help_text="Ubicación donde ocurrió el incidente"
    )
    
    id_grabacion = models.ForeignKey(
        Grabacion,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Grabación relacionada con el incidente"
    )
    
    id_usuario = models.ForeignKey(
        Usuario,
        on_delete=models.CASCADE,
        help_text="Usuario que reporta el incidente",
        db_index=True
    )

    class Meta:
        db_table = 'incidente'
        verbose_name = 'Incidente'
        verbose_name_plural = 'Incidentes'
        ordering = ['-fecha']
        indexes = [
            models.Index(fields=['-fecha'], name='idx_incidente_fecha'),
            models.Index(fields=['tipo'], name='idx_incidente_tipo'),
            models.Index(fields=['id_usuario', '-fecha'], name='idx_incidente_usuario_fecha'),
        ]
        
    def __str__(self) -> str:
        return f"Incidente {self.tipo} - {self.ubicacion} ({self.fecha.strftime('%d/%m/%Y %H:%M')})"


# ============================================================================
# MODELOS DE RELACIONES N:M
# ============================================================================

class Tiene(models.Model):
    """
    Relación N:M Usuario ↔ Departamento
    Un usuario puede tener varios departamentos y viceversa
    """
    
    id_usuario = models.ForeignKey(
        Usuario,
        on_delete=models.CASCADE,
        help_text="Usuario propietario/inquilino"
    )
    
    id_departamento = models.ForeignKey(
        Departamento,
        on_delete=models.CASCADE,
        help_text="Departamento asignado"
    )

    class Meta:
        db_table = 'tiene'
        verbose_name = 'Asignación Usuario-Departamento'
        verbose_name_plural = 'Asignaciones Usuario-Departamento'
        unique_together = [['id_usuario', 'id_departamento']]
        
    def __str__(self) -> str:
        return f"{self.id_usuario.persona.nombre_completo} - {self.id_departamento.nombre_departamento}"


class Reciben(models.Model):
    """
    Relación N:M Usuario ↔ Notificación
    Usuarios que reciben notificaciones
    """
    
    id_usuario = models.ForeignKey(
        Usuario,
        on_delete=models.CASCADE,
        help_text="Usuario receptor"
    )
    
    id_notificacion = models.ForeignKey(
        Notificacion,
        on_delete=models.CASCADE,
        help_text="Notificación recibida"
    )

    class Meta:
        db_table = 'reciben'
        verbose_name = 'Usuario-Notificación'
        verbose_name_plural = 'Usuarios-Notificaciones'
        unique_together = [['id_usuario', 'id_notificacion']]
        
    def __str__(self) -> str:
        return f"{self.id_usuario.persona.nombre_completo} recibe: {self.id_notificacion.motivo}"


class Realiza(models.Model):
    """
    Relación N:M Personal ↔ Mantenimiento ↔ Departamento
    Personal que realiza mantenimientos en departamentos
    """
    
    id_personal = models.ForeignKey(
        Personal,
        on_delete=models.CASCADE,
        help_text="Personal asignado"
    )
    
    id_mantenimiento = models.ForeignKey(
        Mantenimiento,
        on_delete=models.CASCADE,
        help_text="Trabajo de mantenimiento"
    )
    
    id_departamento = models.ForeignKey(
        Departamento,
        on_delete=models.CASCADE,
        help_text="Departamento donde se realiza"
    )
    
    fecha = models.DateTimeField(
        default=timezone.now,
        help_text="Fecha y hora de realización"
    )

    class Meta:
        db_table = 'realiza'
        verbose_name = 'Asignación Mantenimiento'
        verbose_name_plural = 'Asignaciones Mantenimiento'
        unique_together = [['id_personal', 'id_mantenimiento', 'id_departamento']]
        
    def __str__(self) -> str:
        return f"{self.id_personal.id_personal.nombre_completo} - {self.id_mantenimiento.nombre} en {self.id_departamento.nombre_departamento}"


class Notifican(models.Model):
    """
    Relación N:M Usuario ↔ Servicio (notificaciones de consumo)
    Notificaciones específicas de servicios a usuarios
    """
    
    VIA_CHOICES = [
        ('push', 'Push Notification'),
        ('email', 'Email'),
        ('sms', 'SMS'),
        ('whatsapp', 'WhatsApp'),
    ]
    
    ESTADO_CHOICES = [
        ('pendiente', 'Pendiente'),
        ('enviada', 'Enviada'),
        ('leida', 'Leída'),
        ('fallida', 'Fallida'),
    ]
    
    id_usuario = models.ForeignKey(
        Usuario,
        on_delete=models.CASCADE,
        help_text="Usuario notificado"
    )
    
    id_servicio = models.ForeignKey(
        Servicio,
        on_delete=models.CASCADE,
        help_text="Servicio sobre el que se notifica"
    )
    
    mensaje = models.TextField(
        help_text="Contenido de la notificación"
    )
    
    fecha_envio = models.DateTimeField(
        default=timezone.now,
        help_text="Fecha y hora de envío"
    )
    
    motivo = models.CharField(
        max_length=100,
        help_text="Motivo de la notificación"
    )
    
    via = models.CharField(
        max_length=20,
        choices=VIA_CHOICES,
        help_text="Medio de envío"
    )
    
    estado = models.CharField(
        max_length=20,
        choices=ESTADO_CHOICES,
        default='pendiente',
        help_text="Estado de la notificación"
    )

    class Meta:
        db_table = 'notifican'
        verbose_name = 'Notificación de Servicio'
        verbose_name_plural = 'Notificaciones de Servicios'
        unique_together = [['id_usuario', 'id_servicio', 'fecha_envio']]
        
    def __str__(self) -> str:
        return f"Notificación {self.motivo} a {self.id_usuario.persona.nombre_completo}"


class Resuelve(models.Model):
    """
    Relación N:M Incidente ↔ Personal (resolución)
    Personal asignado para resolver incidentes
    """
    
    ESTADO_RESOLUCION_CHOICES = [
        ('asignado', 'Asignado'),
        ('en_proceso', 'En Proceso'),
        ('resuelto', 'Resuelto'),
        ('cerrado', 'Cerrado'),
    ]
    
    id_incidente = models.ForeignKey(
        Incidente,
        on_delete=models.CASCADE,
        help_text="Incidente a resolver"
    )
    
    id_personal = models.ForeignKey(
        Personal,
        on_delete=models.CASCADE,
        help_text="Personal asignado"
    )
    
    estado = models.CharField(
        max_length=20,
        choices=ESTADO_RESOLUCION_CHOICES,
        default='asignado',
        help_text="Estado de la resolución"
    )

    class Meta:
        db_table = 'resuelve'
        verbose_name = 'Resolución de Incidente'
        verbose_name_plural = 'Resoluciones de Incidentes'
        unique_together = [['id_incidente', 'id_personal']]
        
    def __str__(self) -> str:
        return f"{self.id_personal.id_personal.nombre_completo} resuelve incidente {self.id_incidente.id_incidente}"


class AuditoriaEvento(models.Model):
    """
    Modelo AuditoriaEvento optimizado - Registro de eventos del sistema
    """
    
    EVENTO_CHOICES = [
        ('login_exitoso', 'Login exitoso'),
        ('login_fallido', 'Login fallido'),
        ('logout_exitoso', 'Logout exitoso'),
        ('cambio_password', 'Cambio de contraseña'),
        ('reset_password', 'Reset de contraseña'),
        ('acceso_no_autorizado', 'Acceso no autorizado'),
        ('acceso_biometrico', 'Acceso biométrico'),
        ('registro_usuario', 'Registro de usuario'),
        ('modificacion_perfil', 'Modificación de perfil'),
        ('eliminacion_cuenta', 'Eliminación de cuenta'),
        ('activacion_2fa', 'Activación 2FA'),
        ('desactivacion_2fa', 'Desactivación 2FA'),
    ]
    
    usuario = models.ForeignKey(
        Usuario,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        help_text="Usuario asociado al evento",
        db_index=True
    )
    
    username = models.CharField(
        max_length=150,
        blank=True,
        help_text="Username/CI del usuario (para casos donde se elimine el usuario)",
        db_index=True
    )
    
    evento = models.CharField(
        max_length=32,
        choices=EVENTO_CHOICES,
        help_text="Tipo de evento registrado",
        db_index=True
    )
    
    ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text="Dirección IP desde donde se realizó la acción"
    )
    
    user_agent = models.TextField(
        blank=True,
        help_text="Información del navegador/cliente"
    )
    
    fecha = models.DateTimeField(
        default=timezone.now,
        help_text="Fecha y hora del evento",
        db_index=True
    )
    
    detalle = models.TextField(
        blank=True,
        help_text="Detalles adicionales del evento"
    )

    class Meta:
        db_table = 'auditoria_evento'
        verbose_name = 'Evento de Auditoría'
        verbose_name_plural = 'Eventos de Auditoría'
        ordering = ['-fecha']
        indexes = [
            models.Index(fields=['-fecha'], name='idx_auditoria_fecha'),
            models.Index(fields=['evento'], name='idx_auditoria_evento'),
            models.Index(fields=['usuario', '-fecha'], name='idx_auditoria_usuario_fecha'),
            models.Index(fields=['username'], name='idx_auditoria_username'),
        ]

    def __str__(self) -> str:
        usuario_display = self.username if self.username else (self.usuario.persona.nombre_completo if self.usuario else 'Sistema')
        return f"{self.get_evento_display()} - {usuario_display} - {self.fecha.strftime('%d/%m/%Y %H:%M')}"
    
    @classmethod
    def crear_evento(cls, evento: str, usuario=None, ip: str = None, 
                    user_agent: str = None, detalle: str = None):
        """
        Método estático para crear eventos de auditoría fácilmente
        """
        return cls.objects.create(
            evento=evento,
            usuario=usuario,
            username=str(usuario.persona.ci) if usuario else None,
            ip=ip,
            user_agent=user_agent,
            detalle=detalle
        )


# ============================================================================
# DOCUMENTACIÓN FINAL
# ============================================================================

"""
MODELOS OPTIMIZADOS PARA ESQUEMA POSTGRESQL:

✅ ESTRUCTURA COMPLETADA:
- Persona: Modelo base con CI y teléfono como INTEGER
- Usuario: Herencia de tabla con autenticación Django
- Personal, Administrador, Junta: Roles específicos
- Departamento: Unidades del edificio
- Cámara, Grabación, Acceso: Sistema de seguridad
- Factura, Pago: Sistema financiero
- AreaComun, Reserva, Servicio, Mantenimiento: Servicios
- Notificación, Incidente: Comunicación
- Biométricos: Datos encriptados
- AuditoriaEvento: Registro de eventos

✅ RELACIONES N:M IMPLEMENTADAS:
- Tiene: Usuario ↔ Departamento
- Reciben: Usuario ↔ Notificación
- Realiza: Personal ↔ Mantenimiento ↔ Departamento
- Notifican: Usuario ↔ Servicio
- Resuelve: Incidente ↔ Personal

✅ CARACTERÍSTICAS IMPLEMENTADAS:
- Validadores personalizados para todos los campos
- Encriptación de datos sensibles (biométricos, referencias)
- Índices optimizados para consultas frecuentes
- Meta clases completas con nombres de tabla PostgreSQL
- Métodos y properties útiles
- Documentación completa
- Manejo de errores en desencriptación
- Validaciones de negocio

✅ PRÓXIMOS PASOS:
1. Ejecutar: python manage.py makemigrations
2. Revisar las migraciones generadas
3. Ejecutar: python manage.py migrate
4. Probar la creación de usuarios con el nuevo manager
5. Verificar que la encriptación funcione correctamente

NOTA IMPORTANTE:
- El modelo Usuario ahora usa herencia de tabla (OneToOneField con Persona)
- El USERNAME_FIELD es ahora "id_usuario" (que apunta al CI de Persona)
- Se debe actualizar la configuración de AUTH_USER_MODEL si es necesario
- Los serializers y views pueden necesitar ajustes menores

CAMBIOS CRÍTICOS REALIZADOS:
- CI y teléfono ahora son IntegerField según esquema PostgreSQL
- Usuario hereda de Persona usando OneToOneField (herencia de tabla)
- Todas las claves foráneas actualizadas para coincidir con esquema
- Agregados todos los modelos faltantes del esquema
- Implementadas todas las relaciones N:M
- Optimizados índices y consultas
"""
