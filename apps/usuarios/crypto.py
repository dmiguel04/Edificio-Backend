"""
Módulo de criptografía para datos sensibles (NO para contraseñas)

Este módulo se usa ÚNICAMENTE para encriptar datos sensibles como:
- Datos biométricos (huellas, rostro, iris)
- Referencias bancarias 
- Otros datos que necesiten ser recuperables

IMPORTANTE: Las contraseñas ahora usan el sistema de hash seguro de Django
que NO es reversible (no se puede "desencriptar" una contraseña hasheada).
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from django.conf import settings

# Clave de 32 bytes para AES256
SECRET_KEY = settings.SECRET_KEY[:32].encode("utf-8")

def encrypt_sensitive_data(data: str) -> str:
    """
    Encripta datos sensibles (NO contraseñas) usando AES256
    Usado para: biométricos, referencias bancarias, etc.
    """
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
    return base64.b64encode(encrypted).decode("utf-8")

def decrypt_sensitive_data(encrypted_data: str) -> str:
    """
    Desencripta datos sensibles (NO contraseñas) usando AES256
    Usado para: biométricos, referencias bancarias, etc.
    """
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted = unpad(
        cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size
    )
    return decrypted.decode("utf-8")

# Funciones de compatibilidad (mantener hasta actualizar referencias)
def encrypt_password(password: str) -> str:
    """DEPRECATED: Usar encrypt_sensitive_data en su lugar"""
    return encrypt_sensitive_data(password)

def decrypt_password(encrypted_password: str) -> str:
    """DEPRECATED: Usar decrypt_sensitive_data en su lugar"""
    return decrypt_sensitive_data(encrypted_password)
