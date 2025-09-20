# Edificio-Backend

Backend para la gestión de usuarios, autenticación segura y auditoría de eventos en una aplicación de administración de edificios.  
Desarrollado con **Django** y **Django REST Framework**.

---

## Características principales

- Registro y autenticación de usuarios
- Inicio de sesión seguro:
  - Token de un solo uso enviado por correo electrónico
  - Autenticación de dos factores (2FA) con Google Authenticator u otra app compatible (QR y código TOTP)
  - Bloqueo temporal de cuenta tras múltiples intentos fallidos
- Recuperación y cambio de contraseña
- Auditoría de eventos (login, cambios de contraseña, intentos fallidos, etc.)
- Verificación de existencia de persona por CI o email
- Logout seguro con blacklisting de tokens JWT
- Soporte para CORS (integración con frontend Angular)
- Consultas SQL crudas protegidas
- Preparado para integración de biometría como segundo factor

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

| Método | Endpoint                       | Descripción                                      |
|--------|-------------------------------|--------------------------------------------------|
| POST   | `/api/usuarios/register/`      | Registro de usuario                              |
| POST   | `/api/usuarios/login/`         | Login (envía token por correo)                   |
| POST   | `/api/usuarios/validate-login-token/` | Validar token de correo para login        |
| POST   | `/api/usuarios/2fa/verify/`    | Verificar código 2FA                             |
| GET    | `/api/usuarios/2fa/activate/`  | Obtener QR para activar 2FA                      |
| POST   | `/api/usuarios/forgot-password/` | Solicitar recuperación de contraseña           |
| POST   | `/api/usuarios/reset-password/` | Resetear contraseña con token                   |
| POST   | `/api/usuarios/change-password/` | Cambiar contraseña (autenticado)                |
| POST   | `/api/usuarios/logout/`        | Logout y blacklist de token                      |
| GET    | `/api/usuarios/auditoria/`     | Listar eventos de auditoría                      |
| GET    | `/api/usuarios/account-status/`| Consultar estado de bloqueo de cuenta            |
| GET    | `/api/usuarios/check-persona/` | Verificar existencia de persona por CI/email     |
| GET    | `/api/usuarios/raw/`           | Consulta SQL cruda protegida (solo para pruebas) |

---

## Flujo de autenticación

1. **Login:**  
   Usuario y contraseña → `/login/` → Token enviado por correo

2. **Validación de token:**  
   Token de correo → `/validate-login-token/`  
   - Si no tiene 2FA: recibe QR para activar 2FA  
   - Si tiene 2FA: solicita código 2FA

3. **Verificación 2FA:**  
   Código 2FA → `/2fa/verify/` → Recibe tokens JWT (`access` y `refresh`)

---

## Configuración de correo

En `settings.py`, configura tu servidor SMTP:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'tu_correo@gmail.com'
EMAIL_HOST_PASSWORD = 'tu_contraseña_o_app_password'
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
```

Para desarrollo, puedes usar el backend de consola:

```python
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
```

---

## Configuración de zona horaria

Asegúrate de tener tu zona horaria local en `settings.py`:

```python
TIME_ZONE = 'America/La_Paz'  # Cambia según tu país
USE_TZ = True
```

---

## Seguridad y roles

- El backend soporta roles de usuario (puedes extender el modelo `Usuario`).
- El control de acceso a endpoints debe hacerse con permisos personalizados en las vistas.

---

## Auditoría y logs

Todos los eventos importantes (login, fallos, cambios de contraseña, etc.) quedan registrados en la tabla de auditoría.

---

## CORS

El backend permite peticiones desde el frontend Angular (por defecto `http://localhost:4200`).  
Configura otros orígenes en `settings.py` si es necesario.

---

## Consultas SQL crudas

Incluye un endpoint de ejemplo para consultas SQL seguras usando parámetros.

---

## Biometría (comentado)

El código incluye comentarios para una futura integración de biometría como segundo factor.

---

## Licencia

MIT
