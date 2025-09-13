from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from django.conf import settings

# Clave de 32 bytes para AES256
SECRET_KEY = settings.SECRET_KEY[:32].encode("utf-8")

def encrypt_password(password: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(password.encode("utf-8"), AES.block_size))
    return base64.b64encode(encrypted).decode("utf-8")

def decrypt_password(encrypted_password: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    decrypted = unpad(
        cipher.decrypt(base64.b64decode(encrypted_password)), AES.block_size
    )
    return decrypted.decode("utf-8")
