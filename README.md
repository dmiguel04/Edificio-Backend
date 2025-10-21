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

---

## Instalación

1. **Clona el repositorio:**

   ```sh
   git clone https://github.com/dmiguel04/Edificio-Backend.git
   cd Edificio-Backend
   ```

2. **Crea y activa un entorno virtual:**

   ```sh
   python -m venv venv
   venv\Scripts\activate  # En Windows
   ```

3. **Instala las dependencias:**

   ```sh
   pip install -r requirements.txt
   ```

4. **Configura las variables de entorno y correo** en `edificiobackend/settings.py` (ver sección de configuración).

5. **Aplica migraciones:**

   ```sh
   python manage.py migrate
   ```

6. **Crea un superusuario (opcional):**

   ```sh
   python manage.py createsuperuser
   ```

7. **Inicia el servidor:**

   ```sh
   python manage.py runserver
   ```

---

## Endpoints principales

### 🔗 **Endpoints de Autenticación**
| Método | Endpoint                       | Descripción                                      |
|--------|-------------------------------|--------------------------------------------------|
| POST   | `/api/usuarios/register/`      | Registro con verificación de email               |
| POST   | `/api/usuarios/login/`         | Login con validación de email verificado         |
| POST   | `/api/usuarios/verificar-email/` | Verificar email con código de 6 dígitos        |
| POST   | `/api/usuarios/reenviar-verificacion/` | Reenviar código de verificación          |

### 🔐 **Endpoints de 2FA y Tokens**
| Método | Endpoint                       | Descripción                                      |
|--------|-------------------------------|--------------------------------------------------|
| POST   | `/api/usuarios/validate-login-token/` | Validar token de correo para login        |
| POST   | `/api/usuarios/2fa/verify/`    | Verificar código 2FA                             |
| GET    | `/api/usuarios/2fa/activate/`  | Obtener QR para activar 2FA                      |

### 🚪 **Endpoints de Logout**
| Método | Endpoint                       | Descripción                                      |
|--------|-------------------------------|--------------------------------------------------|
| POST   | `/api/usuarios/logout/`        | Logout optimizado con timeout                    |
| POST   | `/api/usuarios/logout-all/`    | Logout masivo (cerrar todas las sesiones)        |

### 🔒 **Endpoints de Contraseña**
| Método | Endpoint                       | Descripción                                      |
|--------|-------------------------------|--------------------------------------------------|
| POST   | `/api/usuarios/forgot-password/` | Solicitar recuperación de contraseña           |
| POST   | `/api/usuarios/reset-password/` | Resetear contraseña con token                   |
| POST   | `/api/usuarios/change-password/` | Cambiar contraseña (autenticado)                |

### 📊 **Endpoints de Consulta**
| Método | Endpoint                       | Descripción                                      |
|--------|-------------------------------|--------------------------------------------------|
| GET    | `/api/usuarios/auditoria/`     | Listar eventos de auditoría                      |
| GET    | `/api/usuarios/account-status/`| Consultar estado de bloqueo de cuenta            |
| GET    | `/api/usuarios/check-persona/` | Verificar existencia de persona por CI/email     |
| GET    | `/api/usuarios/raw/`           | Consulta SQL cruda protegida (solo para pruebas) |

---

## 🔄 Flujo de autenticación

### 📝 **1. Registro de Usuario**
```
Datos usuario → /register/ → Email enviado → /verificar-email/ → Usuario activo
```

### 🔐 **2. Login Estándar** 
```
Usuario/Password → /login/ → Token enviado por correo → /validate-login-token/
```

### 🔒 **3. Login con 2FA**
```
Login exitoso → /2fa/activate/ (QR) → /2fa/verify/ → JWT tokens
```

### 🎫 **4. Tokens JWT**
- **Access Token**: 15 minutos (para peticiones API)
- **Refresh Token**: 1 día (para renovar access token)
- **Rotación automática**: Nuevos tokens en cada renovación
- **Blacklist**: Tokens viejos se invalidan automáticamente

### 🚪 **5. Logout Inteligente**
```
/logout/ → Blacklist inmediato → Respuesta rápida (< 200ms)
/logout-all/ → Cierra todas las sesiones → Logout masivo
```

---

## 📧 Configuración de correo

### 🚀 **Producción (SMTP)**
En `settings.py`, configura tu servidor SMTP:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'tu_correo@gmail.com'
EMAIL_HOST_PASSWORD = 'tu_app_password'  # Contraseña de aplicación
DEFAULT_FROM_EMAIL = 'noreply@edificioapp.com'
```

### 🔧 **Desarrollo (Consola)**
Para desarrollo, usa el backend de consola:

```python
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```

### 📧 **Sistema de Verificación**
- **Códigos de 6 dígitos** (ejemplo: `123456`)
- **Expiración**: 24 horas
- **Reenvío automático** disponible
- **Templates personalizados** para cada tipo de email

---

## Configuración de zona horaria

Asegúrate de tener tu zona horaria local en `settings.py`:

```python
TIME_ZONE = 'America/La_Paz'  # Cambia según tu país
USE_TZ = True
```

---

## 🛡️ Seguridad Implementada

### 🔐 **Hashing de Contraseñas**
```python
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',     # PBKDF2-SHA256 (870k iteraciones)
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher', # PBKDF2-SHA1 (compatibilidad)
    'django.contrib.auth.hashers.ScryptPasswordHasher',     # Scrypt (alternativa)
]
```

### 🔒 **Headers de Seguridad**
```python
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
```

### 🚨 **Protecciones Activas**
- ✅ **Bloqueo de cuentas** tras 3 intentos fallidos
- ✅ **Rate limiting** en endpoints críticos
- ✅ **Sanitización HTML** en inputs de usuario
- ✅ **Consultas SQL parametrizadas** contra inyección
- ✅ **Encriptación AES-256** para datos sensibles

---

## 📊 Auditoría y Logs

### 📝 **Eventos Rastreados**
- `login_exitoso` - Inicio de sesión correcto
- `login_fallido` - Intento de login fallido
- `logout_exitoso` - Cierre de sesión
- `cambio_password` - Cambio de contraseña
- `reset_password` - Recuperación de contraseña
- `acceso_no_autorizado` - Acceso sin permisos

### 🔍 **Información Capturada**
```json
{
  "usuario": "davidmachicado",
  "evento": "login_exitoso",
  "ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "fecha": "2025-09-25T10:30:00Z",
  "detalle": "Login desde nueva IP"
}
```

---

## 🌐 CORS y Frontend

### 🔗 **Configuración CORS**
```python
CORS_ALLOW_ALL_ORIGINS = True  # Solo para desarrollo
CORS_ALLOWED_ORIGINS = [
    "http://localhost:4200",  # Angular dev server
    "https://tu-frontend.com"  # Producción
]
```

### 📱 **Compatibilidad**
- ✅ **Angular** (configurado por defecto)
- ✅ **React** / **Vue.js** (configuración manual)
- ✅ **Aplicaciones móviles** (con headers apropiados)

---

## 🔬 Características Avanzadas

### 🧬 **Preparado para Biometría**
- Modelos para datos biométricos (huellas, rostro, iris)
- Encriptación AES-256 para datos biométricos
- Arquitectura lista para WebAuthn

### 🗃️ **Consultas SQL Seguras**
```python
# Ejemplo de consulta parametrizada
cursor.execute(
    "SELECT username FROM usuarios_usuario WHERE email = %s", 
    [email_parametro]
)
```

### 🔄 **Migraciones Optimizadas**
- Migración inicial consolidada
- Eliminación de migraciones redundantes
- Schema optimizado para producción

---

## 🚀 Roadmap

### 📋 **Próximas Características**
- [ ] **Detección de nuevos dispositivos** basada en User-Agent e IP
- [ ] **Notificaciones por email** para logins desde nuevos dispositivos  
- [ ] **Endpoint de cambio de contraseña** con logout masivo automático
- [ ] **Dashboard de seguridad** con métricas en tiempo real
# Edificio-Backend 🏢

Backend para gestión de usuarios, autenticación segura, auditoría y administración de un edificio.
Implementado con Django 5.x y Django REST Framework. Este README recoge lo esencial para desarrollar, probar y usar los endpoints principales —especialmente el módulo de gestión de usuarios (`apps.gestion_usuarios`).

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
  - POST /api/usuarios/register/
  - POST /api/usuarios/login/ (inicia login — backend envía `login_token` por email)
  - POST /api/usuarios/validate-login-token/ (validar token enviado por email)
  - POST /api/usuarios/2fa/verify/ (verificar TOTP → devuelve access/refresh)
  - POST /api/usuarios/reset-password/ (reset con token)
  - POST /api/usuarios/forgot-password/
  - GET /api/usuarios/2fa/activate/ (retorna QR como data URL)
  - POST /api/usuarios/change-password/ (autenticado)

- Gestión de usuarios (`apps.gestion_usuarios` - ViewSet `UsuarioViewSet`):
  - GET  /api/gestion-usuarios/usuarios/ (listar)
  - POST /api/gestion-usuarios/usuarios/ (crear — admin o junta con restricciones)
  - GET  /api/gestion-usuarios/usuarios/{id}/
  - PATCH/PUT /api/gestion-usuarios/usuarios/{id}/
  - DELETE /api/gestion-usuarios/usuarios/{id}/
  - POST /api/gestion-usuarios/usuarios/{id}/assign-role/  (admin)
  - POST /api/gestion-usuarios/usuarios/{id}/set-active/  (admin)
  - POST /api/gestion-usuarios/usuarios/change-password/  (propio o admin-forzar)

Notas: la mayoría de endpoints requieren `Authorization: Bearer <access>` salvo los marcados como AllowAny (registro/login/request-initial-reset).

---

## Flujo recomendado para usuario creado por admin (primer acceso)

Cuando un admin crea un usuario la API genera un `reset_password_token`, marca `must_change_password = true` y envía un enlace de configuración. Flujo de primer acceso:

1. Usuario recibe link: `https://frontend/reset-password?token=...&u=username`.
2. En la UI, usar `/api/usuarios/reset-password/` con `{ token, new_password }`.
3. Tras reset exitoso: iniciar login normal `/api/usuarios/login/` → backend envía `login_token` por email.
4. Validar login token `/api/usuarios/validate-login-token/` → si no hay 2FA, se devuelve `qr_url` para activar; si hay 2FA devuelve `require_2fa`.
5. Verificar 2FA `/api/usuarios/2fa/verify/` → devuelve `access` y `refresh` JWT.

He incluido además un endpoint público seguro para solicitar el link de primer acceso (no revela existencia):
- POST `/api/usuarios/request-initial-reset/` with `{ "username_or_email" }` — envía enlace si corresponde.

---

## Pruebas y Postman

- Hay una colección de Postman (exportable) incluida en el repo: `postman_collections/edificioapp_admin_user.postman_collection.json` (si necesitas la guardo en el workspace).
- Pruebas rápidas:
  - Ejecutar tests del módulo de gestión: `python manage.py test apps.gestion_usuarios.tests -v2`
  - Ejecutar toda la suite: `python manage.py test`

---

## Configuración de correo para desarrollo

- En desarrollo es práctico usar consola para ver tokens en stdout:

```py
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```

En producción configurar SMTP en `settings.py` (GMail u otro proveedor).

---

## Tokens y expiraciones (SIMPLE_JWT)

- ACCESS_TOKEN_LIFETIME: 15 minutos (por defecto)
- REFRESH_TOKEN_LIFETIME: 1 día
- Rotación y blacklist activados

Si en pruebas ves `token_not_valid` o `Token is expired`, usa el refresh token o re-loguea mediante el flujo 2FA.

---

## Migraciones y notas de DB

- Se añadieron migraciones para soportar `must_change_password` y campos nuevos. Si trabajas en local:

```powershell
python manage.py makemigrations
python manage.py migrate
```

---

## Testing y CI

- Los tests del módulo `apps.gestion_usuarios` están presentes y se han corrido localmente. Ejecuta:

```powershell
python manage.py test apps.gestion_usuarios.tests -v2
```

---

## Git / deploy

- Commit y push: `git add -A && git commit -m "..." && git push origin main` (en PowerShell separa comandos).

---

## Próximos pasos sugeridos

- Envío de correos asíncronos (Celery) y plantillas HTML.
- Tests que mockeen `send_mail` para verificar envíos en CI.
- Mejoras en seguridad y dashboard de auditoría.

---

Si quieres que añada la colección Postman al repo (archivo JSON) o que implemente/active el endpoint `request-initial-reset` y cree tests automáticos, dímelo y lo hago.

---

**Autor:** David Machicado — https://github.com/dmiguel04
