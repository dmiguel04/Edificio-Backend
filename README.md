# Edificio-Backend 🏢

Backend robusto para la gestión de usuarios, autenticación segura y auditoría de eventos en una aplicación de administración de edificios.  
Desarrollado con **Django 5.2.6** y **Django REST Framework**.

---

## 🚀 Características principales

### 🔐 **Sistema de Autenticación Avanzado**
- **Registro de usuarios** con validación de datos personal
- **Verificación de email** con códigos de 6 dígitos (24h expiración)
- **Hashing seguro de contraseñas** con PBKDF2-SHA256 (870,000 iteraciones)
- **Autenticación JWT** con tokens de corta duración (15min access, 1 día refresh)
- **Autenticación de dos factores (2FA)** con Google Authenticator
- **Bloqueo automático** tras múltiples intentos fallidos

### 🚪 **Sistema de Logout Inteligente**
- **Logout optimizado** con timeouts para mejor UX
- **Logout masivo** para cerrar todas las sesiones del usuario
- **Blacklisting automático** de tokens JWT
- **Rotación de tokens** para mayor seguridad

### 📧 **Sistema de Comunicación**
- **Verificación por email** con códigos numéricos
- **Reenvío de códigos** de verificación
- **Recuperación de contraseña** segura
- **Configuración SMTP** para producción

### 📊 **Auditoría y Monitoreo**
- **Registro completo** de eventos de seguridad
- **Tracking de IPs** y User-Agents
- **Detección de patrones** de login sospechosos
- **Reportes de auditoría** filtrados por evento

### 🛡️ **Seguridad Empresarial**
- **Encriptación AES-256** para datos sensibles
- **Headers de seguridad** configurados
- **Validación de entrada** con sanitización HTML
- **Consultas SQL** parametrizadas y seguras
- **Preparado para biometría** como segundo factor
# Edificio-Backend

Backend para gestión de usuarios, autenticación segura y auditoría de eventos en una aplicación de administración de edificios.
Implementado con Django 5.x y Django REST Framework. Este README se ha reducido y ordenado para mantener lo esencial: quickstart, endpoints clave, flujo de primer acceso y notas de configuración.

---

## Objetivo

Proveer una API segura para:
- Registro y verificación por correo.
- Login con token enviado por correo y doble factor (2FA).
- Gestión de usuarios y roles (administrador, junta, personal, residente).
- Auditoría de eventos de seguridad.

---

## Quickstart (desarrollo)

1. Clona el repo:

```powershell
git clone https://github.com/dmiguel04/Edificio-Backend.git
cd Edificio-Backend
```

2. Entorno virtual e instalación:

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

3. Configura variables en `edificiobackend/settings.py` (email, AES_KEY_B64, DB).

4. Migraciones y arranque:

```powershell
python manage.py migrate
python manage.py createsuperuser  # opcional
python manage.py runserver
```

---

## Endpoints clave (resumen)

Base URL (dev): `http://localhost:8000`

- Auth & usuario (`apps.usuarios`):
   - POST `/api/usuarios/register/`
   - POST `/api/usuarios/login/` (inicia login — backend envía `login_token` por email)
   - POST `/api/usuarios/validate-login-token/`
   - POST `/api/usuarios/2fa/verify/` (verificar TOTP → devuelve access/refresh)
   - GET  `/api/usuarios/2fa/activate/` (retorna QR como data URL)
   - POST `/api/usuarios/forgot-password/`
   - POST `/api/usuarios/reset-password/`
   - POST `/api/usuarios/change-password/` (autenticado)

- Gestión de usuarios (`apps.gestion_usuarios` - ViewSet `UsuarioViewSet`):
   - GET  `/api/gestion-usuarios/usuarios/` (listar)
   - POST `/api/gestion-usuarios/usuarios/` (crear — admin o junta con restricciones)
   - GET/PATCH/PUT/DELETE `/api/gestion-usuarios/usuarios/{id}/`
   - POST `/api/gestion-usuarios/usuarios/{id}/assign-role/`  (admin)
   - POST `/api/gestion-usuarios/usuarios/{id}/set-active/`  (admin)

Notas: la mayoría de endpoints requieren `Authorization: Bearer <access>` salvo los marcados como AllowAny (registro/login/request-initial-reset).

---

## Flujo recomendado para usuario creado por admin (primer acceso)

Cuando un admin crea un usuario la API genera un `reset_password_token`, marca `must_change_password = true` y envía un enlace de configuración. Flujo resumido:

1. Usuario recibe link en email: `https://frontend/reset-password?token=...&u=username`.
2. En la UI el usuario llama `/api/usuarios/reset-password/` con `{ "token": "...", "password": "..." }`.
3. Tras reset exitoso puede iniciar `/api/usuarios/login/` → backend envía `login_token` por email.
4. Validar login token con `/api/usuarios/validate-login-token/`.
5. Si aplica 2FA, activar con `/api/usuarios/2fa/activate/` y verificar con `/api/usuarios/2fa/verify/` para obtener JWT.

Además existe un endpoint público seguro para solicitar el link de primer acceso sin revelar existencia:

- POST `/api/usuarios/request-initial-reset/` con `{ "username_or_email": "..." }`.

---

## Configuración de correo

En desarrollo es práctico usar el backend de consola:

```py
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```

Para producción configura SMTP en `edificiobackend/settings.py` (GMail u otro proveedor):

```py
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.example.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'tu_correo@example.com'
EMAIL_HOST_PASSWORD = 'tu_app_password'
DEFAULT_FROM_EMAIL = 'noreply@edificioapp.com'
```

Expiraciones y comportamiento:
- Códigos de verificación: 6 dígitos, expiración 24h.
- Reset tokens: expiración configurable (por defecto 24h).

---

## Tokens y expiraciones (SIMPLE_JWT)

- ACCESS_TOKEN_LIFETIME: 15 minutos
- REFRESH_TOKEN_LIFETIME: 1 día
- Rotación y blacklist activados

Si ves `token_not_valid` o `Token is expired`, usa el refresh token o repite el flujo de autenticación.

---

## Migraciones y notas de DB

Se añadieron migraciones para soportar `must_change_password` y campos nuevos. En local:

```powershell
python manage.py makemigrations
python manage.py migrate
```

---

## Pruebas y Postman

- Ejecutar tests del módulo de gestión:

```powershell
python manage.py test apps.gestion_usuarios.tests -v2
```

- Hay una colección Postman exportable (puedo añadir `postman_collections/` al repo si quieres).

---

## Sugerencias / próximos pasos

- Envío de correos asíncronos (Celery) y plantillas HTML.
- Tests que mockeen `send_mail` para verificar envíos en CI.
- Implementar/ajustar endpoint `request-initial-reset` según UX.

---

**Autor:** David Machicado — https://github.com/dmiguel04
```
