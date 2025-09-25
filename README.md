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
- [ ] **Integración con WebAuthn** para autenticación biométrica

### 🔧 **Mejoras Técnicas Planificadas**
- [ ] **Redis** para caché de sesiones
- [ ] **Celery** para tareas en background
- [ ] **Docker** containerization
- [ ] **API versioning** y documentación OpenAPI
- [ ] **Tests automatizados** con cobertura >90%

---

## 📈 Performance

### ⚡ **Optimizaciones Implementadas**
- **Logout < 200ms**: Respuesta inmediata sin bloquear frontend
- **JWT Blacklisting**: Procesamiento en background
- **Consultas optimizadas**: Índices en campos críticos
- **Timeout inteligente**: Renovación automática de tokens

### 📊 **Métricas de Referencia**
- **Login**: ~500ms (incluyendo envío de email)
- **Verificación 2FA**: ~100ms
- **Logout**: <200ms (garantizado)
- **Consulta auditoría**: ~50ms (con filtros)

---

## 🤝 Contribución

1. **Fork** el repositorio
2. **Crea** una rama para tu feature (`git checkout -b feature/nueva-caracteristica`)
3. **Commit** tus cambios (`git commit -m 'Add: nueva característica'`)
4. **Push** a la rama (`git push origin feature/nueva-caracteristica`)
5. **Abre** un Pull Request

---

## 📄 Licencia

MIT License - Ver [LICENSE](LICENSE) para más detalles.

---

## 👨‍💻 Autor

**David Machicado** - [@dmiguel04](https://github.com/dmiguel04)

---

<div align="center">

### ⭐ Si te gusta este proyecto, ¡dale una estrella! ⭐

**Hecho con ❤️ y Django**

</div>
