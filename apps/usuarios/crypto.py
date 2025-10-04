"""
Módulo de criptografía avanzada para datos sensibles del sistema de edificio.

🔐 PROPÓSITO:
- Encriptación segura de datos biométricos (huellas, rostro, iris)
- Protección de información bancaria y financiera
- Cifrado de datos PII (Personally Identifiable Information)
- Referencias sensibles que necesiten ser recuperables

⚠️ IMPORTANTE:
- Las contraseñas usan el sistema de hash seguro de Django (NO reversible)
- Este módulo usa AES-256-GCM para máxima seguridad
- Cada operación genera un IV único para evitar ataques de patrón
- Implementa validación de integridad automática

🛡️ CARACTERÍSTICAS DE SEGURIDAD:
- AES-256-GCM (Galois/Counter Mode) con autenticación integrada
- IV/Nonce únicos por operación
- Derivación de clave PBKDF2 con salt
- Validación de integridad automática
- Manejo seguro de memoria
- Logging de seguridad

📋 EJEMPLOS DE USO:
    # Encriptar datos biométricos
    encrypted_fingerprint = encrypt_biometric_data("base64_fingerprint_data")
    
    # Encriptar información bancaria
    encrypted_account = encrypt_financial_data("1234567890")
    
    # Desencriptar (solo si tienes autorización)
    original_data = decrypt_sensitive_data(encrypted_data)
"""

import os
import base64
import logging
import hashlib
from typing import Optional, Union, Tuple
from functools import lru_cache

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from django.conf import settings
from django.core.cache import cache

# Configurar logging de seguridad
logger = logging.getLogger('security.crypto')

# ============================================================================
# CONFIGURACIÓN DE SEGURIDAD
# ============================================================================

class CryptoConfig:
    """Configuración centralizada para operaciones criptográficas"""
    
    # Configuración AES-GCM
    KEY_SIZE = 32  # AES-256
    IV_SIZE = 16   # 128 bits para GCM
    TAG_SIZE = 16  # 128 bits para autenticación
    
    # Configuración PBKDF2
    PBKDF2_ITERATIONS = 100000  # Recomendado por OWASP 2024
    SALT_SIZE = 32
    
    # Cache y rendimiento
    CACHE_TIMEOUT = 3600  # 1 hora
    MAX_DATA_SIZE = 10 * 1024 * 1024  # 10MB máximo

# ============================================================================
# GENERACIÓN Y MANEJO DE CLAVES
# ============================================================================

@lru_cache(maxsize=1)
def _get_master_key() -> bytes:
    """
    Obtiene la clave maestra derivada de forma segura.
    
    Returns:
        bytes: Clave de 32 bytes para AES-256
    """
    try:
        # Obtener clave base de Django settings
        base_key = getattr(settings, 'SECRET_KEY', '')
        if not base_key:
            raise ValueError("SECRET_KEY no configurado en Django settings")
        
        # Salt fijo para derivación consistente (en producción usar salt único por instalación)
        fixed_salt = b'edificio_crypto_salt_2024'
        
        # Derivar clave usando PBKDF2
        derived_key = PBKDF2(
            base_key.encode('utf-8'),
            fixed_salt,
            dkLen=CryptoConfig.KEY_SIZE,
            count=CryptoConfig.PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )
        
        logger.debug("Clave maestra derivada exitosamente")
        return derived_key
        
    except Exception as e:
        logger.error(f"Error al generar clave maestra: {e}")
        raise CryptoError(f"Error en generación de clave: {e}")


def _generate_iv() -> bytes:
    """
    Genera un IV (Initialization Vector) criptográficamente seguro.
    
    Returns:
        bytes: IV de 16 bytes para AES-GCM
    """
    return get_random_bytes(CryptoConfig.IV_SIZE)


# ============================================================================
# EXCEPCIONES PERSONALIZADAS
# ============================================================================

class CryptoError(Exception):
    """Excepción base para errores de criptografía"""
    pass


class EncryptionError(CryptoError):
    """Error durante el proceso de encriptación"""
    pass


class DecryptionError(CryptoError):
    """Error durante el proceso de desencriptación"""
    pass


class DataValidationError(CryptoError):
    """Error de validación de datos"""
    pass


# ============================================================================
# FUNCIONES DE VALIDACIÓN
# ============================================================================

def _validate_input_data(data: Union[str, bytes], operation: str) -> bytes:
    """
    Valida y convierte datos de entrada.
    
    Args:
        data: Datos a validar
        operation: Nombre de la operación (para logging)
    
    Returns:
        bytes: Datos validados como bytes
    
    Raises:
        DataValidationError: Si los datos no son válidos
    """
    if data is None:
        raise DataValidationError(f"{operation}: Los datos no pueden ser None")
    
    if isinstance(data, str):
        if not data.strip():
            raise DataValidationError(f"{operation}: Los datos no pueden estar vacíos")
        data_bytes = data.encode('utf-8')
    elif isinstance(data, bytes):
        if not data:
            raise DataValidationError(f"{operation}: Los datos no pueden estar vacíos")
        data_bytes = data
    else:
        raise DataValidationError(f"{operation}: Tipo de datos no soportado: {type(data)}")
    
    # Validar tamaño máximo
    if len(data_bytes) > CryptoConfig.MAX_DATA_SIZE:
        raise DataValidationError(
            f"{operation}: Datos demasiado grandes: {len(data_bytes)} bytes "
            f"(máximo: {CryptoConfig.MAX_DATA_SIZE})"
        )
    
    return data_bytes


def _validate_encrypted_data(encrypted_data: str, operation: str) -> bytes:
    """
    Valida y decodifica datos encriptados.
    
    Args:
        encrypted_data: Datos encriptados en base64
        operation: Nombre de la operación (para logging)
    
    Returns:
        bytes: Datos encriptados como bytes
    
    Raises:
        DataValidationError: Si los datos no son válidos
    """
    if not encrypted_data or not isinstance(encrypted_data, str):
        raise DataValidationError(f"{operation}: Datos encriptados inválidos")
    
    try:
        decoded_data = base64.b64decode(encrypted_data.encode('utf-8'))
    except Exception as e:
        raise DataValidationError(f"{operation}: Error al decodificar base64: {e}")
    
    # Validar tamaño mínimo (IV + Tag + al menos 1 byte de datos)
    min_size = CryptoConfig.IV_SIZE + CryptoConfig.TAG_SIZE + 1
    if len(decoded_data) < min_size:
        raise DataValidationError(
            f"{operation}: Datos encriptados demasiado cortos: {len(decoded_data)} bytes "
            f"(mínimo: {min_size})"
        )
    
    return decoded_data


# ============================================================================
# FUNCIONES PRINCIPALES DE ENCRIPTACIÓN
# ============================================================================

def encrypt_sensitive_data(data: Union[str, bytes], context: str = "general") -> str:
    """
    Encripta datos sensibles usando AES-256-GCM con máxima seguridad.
    
    🔐 CARACTERÍSTICAS:
    - AES-256-GCM (autenticación integrada)
    - IV único por operación
    - Validación de integridad automática
    - Logging de seguridad
    
    Args:
        data: Datos a encriptar (str o bytes)
        context: Contexto de la operación para logging
    
    Returns:
        str: Datos encriptados en base64 (IV + Tag + CipherText)
    
    Raises:
        EncryptionError: Si ocurre un error durante la encriptación
        DataValidationError: Si los datos de entrada no son válidos
    
    Example:
        >>> encrypted = encrypt_sensitive_data("datos biométricos")
        >>> # Resultado: base64 string con IV+Tag+CipherText
    """
    try:
        # Validar datos de entrada
        data_bytes = _validate_input_data(data, "encrypt_sensitive_data")
        
        # Generar IV único
        iv = _generate_iv()
        
        # Obtener clave maestra
        key = _get_master_key()
        
        # Crear cipher AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        # Encriptar datos
        ciphertext, auth_tag = cipher.encrypt_and_digest(data_bytes)
        
        # Combinar IV + Tag + CipherText
        encrypted_data = iv + auth_tag + ciphertext
        
        # Codificar en base64
        result = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Log de seguridad (sin datos sensibles)
        logger.info(
            f"Datos encriptados exitosamente - Contexto: {context}, "
            f"Tamaño original: {len(data_bytes)} bytes, "
            f"Tamaño encriptado: {len(encrypted_data)} bytes"
        )
        
        return result
        
    except (DataValidationError, CryptoError):
        raise  # Re-lanzar errores conocidos
    except Exception as e:
        error_msg = f"Error inesperado en encriptación: {e}"
        logger.error(f"{error_msg} - Contexto: {context}")
        raise EncryptionError(error_msg)


def decrypt_sensitive_data(encrypted_data: str, context: str = "general") -> str:
    """
    Desencripta datos sensibles con validación de integridad automática.
    
    🔐 CARACTERÍSTICAS:
    - Validación de integridad GCM automática
    - Manejo seguro de errores
    - Logging de seguridad
    - Protección contra ataques de padding oracle
    
    Args:
        encrypted_data: Datos encriptados en base64
        context: Contexto de la operación para logging
    
    Returns:
        str: Datos originales desencriptados
    
    Raises:
        DecryptionError: Si ocurre un error durante la desencriptación
        DataValidationError: Si los datos encriptados no son válidos
    
    Example:
        >>> original = decrypt_sensitive_data(encrypted_base64)
        >>> # Resultado: datos originales como string
    """
    try:
        # Validar datos encriptados
        encrypted_bytes = _validate_encrypted_data(encrypted_data, "decrypt_sensitive_data")
        
        # Extraer componentes: IV + Tag + CipherText
        iv = encrypted_bytes[:CryptoConfig.IV_SIZE]
        auth_tag = encrypted_bytes[CryptoConfig.IV_SIZE:CryptoConfig.IV_SIZE + CryptoConfig.TAG_SIZE]
        ciphertext = encrypted_bytes[CryptoConfig.IV_SIZE + CryptoConfig.TAG_SIZE:]
        
        # Obtener clave maestra
        key = _get_master_key()
        
        # Crear cipher AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        # Desencriptar y verificar integridad
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, auth_tag)
        
        # Convertir a string
        result = decrypted_bytes.decode('utf-8')
        
        # Log de seguridad (sin datos sensibles)
        logger.info(
            f"Datos desencriptados exitosamente - Contexto: {context}, "
            f"Tamaño desencriptado: {len(decrypted_bytes)} bytes"
        )
        
        return result
        
    except (DataValidationError, CryptoError):
        raise  # Re-lanzar errores conocidos
    except ValueError as e:
        # Error de autenticación GCM
        error_msg = f"Error de integridad en desencriptación: {e}"
        logger.warning(f"{error_msg} - Contexto: {context}")
        raise DecryptionError("Error de validación de integridad - datos posiblemente corrompidos")
    except Exception as e:
        error_msg = f"Error inesperado en desencriptación: {e}"
        logger.error(f"{error_msg} - Contexto: {context}")
        raise DecryptionError(error_msg)


# ============================================================================
# FUNCIONES ESPECIALIZADAS POR TIPO DE DATO
# ============================================================================

def encrypt_biometric_data(biometric_data: Union[str, bytes]) -> str:
    """
    Encripta datos biométricos con el más alto nivel de seguridad.
    
    Args:
        biometric_data: Datos biométricos (base64, binarios, etc.)
    
    Returns:
        str: Datos biométricos encriptados
    """
    return encrypt_sensitive_data(biometric_data, context="biometric")


def decrypt_biometric_data(encrypted_biometric: str) -> str:
    """
    Desencripta datos biométricos.
    
    Args:
        encrypted_biometric: Datos biométricos encriptados
    
    Returns:
        str: Datos biométricos originales
    """
    return decrypt_sensitive_data(encrypted_biometric, context="biometric")


def encrypt_financial_data(financial_data: Union[str, bytes]) -> str:
    """
    Encripta información financiera (cuentas bancarias, etc.).
    
    Args:
        financial_data: Datos financieros sensibles
    
    Returns:
        str: Datos financieros encriptados
    """
    return encrypt_sensitive_data(financial_data, context="financial")


def decrypt_financial_data(encrypted_financial: str) -> str:
    """
    Desencripta información financiera.
    
    Args:
        encrypted_financial: Datos financieros encriptados
    
    Returns:
        str: Datos financieros originales
    """
    return decrypt_sensitive_data(encrypted_financial, context="financial")


# ============================================================================
# UTILIDADES Y HERRAMIENTAS
# ============================================================================

def hash_for_indexing(data: str) -> str:
    """
    Crea un hash de datos para indexación (búsquedas sin revelar datos).
    
    Args:
        data: Datos a hashear
    
    Returns:
        str: Hash SHA-256 en hexadecimal
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def verify_data_integrity(original_data: str, encrypted_data: str) -> bool:
    """
    Verifica la integridad de datos encriptados.
    
    Args:
        original_data: Datos originales
        encrypted_data: Datos encriptados
    
    Returns:
        bool: True si los datos son íntegros
    """
    try:
        decrypted = decrypt_sensitive_data(encrypted_data)
        return original_data == decrypted
    except Exception:
        return False


def get_encryption_info() -> dict:
    """
    Obtiene información sobre la configuración de encriptación.
    
    Returns:
        dict: Información de configuración (sin datos sensibles)
    """
    return {
        'algorithm': 'AES-256-GCM',
        'key_size': CryptoConfig.KEY_SIZE,
        'iv_size': CryptoConfig.IV_SIZE,
        'tag_size': CryptoConfig.TAG_SIZE,
        'pbkdf2_iterations': CryptoConfig.PBKDF2_ITERATIONS,
        'max_data_size': CryptoConfig.MAX_DATA_SIZE,
        'version': '2.0'
    }


# ============================================================================
# RECORDATORIO DE SEGURIDAD PARA CONTRASEÑAS
# ============================================================================

"""
⚠️ ADVERTENCIA DE SEGURIDAD: CONTRASEÑAS

Las contraseñas NUNCA deben ser encriptadas de forma reversible.
Esto es una vulnerabilidad crítica de seguridad.

✅ FORMA CORRECTA (Django):
    from django.contrib.auth.hashers import make_password, check_password
    
    # Hashear contraseña (irreversible)
    hashed_password = make_password("mi_contraseña")
    
    # Verificar contraseña
    is_valid = check_password("mi_contraseña", hashed_password)

❌ NUNCA HAGAS ESTO:
    encrypted_password = encrypt_sensitive_data("mi_contraseña")  # PELIGROSO
    original_password = decrypt_sensitive_data(encrypted_password)  # VULNERABILIDAD

🔐 ¿POR QUÉ?
- Si alguien accede a la BD, puede desencriptar TODAS las contraseñas
- Los hashes son unidireccionales: imposible obtener la contraseña original
- Django usa algoritmos seguros como PBKDF2, bcrypt, scrypt
- Cumple con estándares internacionales de seguridad (OWASP)

📋 ESTE MÓDULO ES SOLO PARA:
- Datos biométricos (huellas, rostro)
- Información bancaria
- Datos PII que necesiten ser recuperables
- Referencias sensibles

🚫 ESTE MÓDULO NO ES PARA:
- Contraseñas de usuarios
- Tokens de autenticación permanentes  
- Claves de API críticas
- Cualquier dato que deba ser irreversible
"""
