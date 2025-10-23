import json
import logging
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

logger = logging.getLogger(__name__)

class DebugResponseBodyMiddleware(MiddlewareMixin):
    """Middleware de desarrollo que imprime/loggea el body JSON de las respuestas.

    - Solo activo cuando settings.DEBUG es True.
    - Trata de decodificar respuestas JSON/bytes y las trunca a un tamaño seguro.
    - No modifica la respuesta.
    """
    MAX_BYTES = 10 * 1024  # 10 KB

    def process_response(self, request, response):
        try:
            if not getattr(settings, 'DEBUG', False):
                return response

            content_type = response.get('Content-Type', '')
            if 'application/json' in content_type or 'text/' in content_type:
                # response.content puede ser bytes o str
                raw = response.content
                if isinstance(raw, bytes):
                    try:
                        text = raw.decode(response.charset or 'utf-8')
                    except Exception:
                        text = raw.decode('utf-8', errors='replace')
                else:
                    text = str(raw)

                # intentar parsear JSON para formatear
                parsed = None
                try:
                    parsed = json.loads(text)
                except Exception:
                    parsed = None

                display = parsed if parsed is not None else text

                # truncar si es demasiado grande
                dump = json.dumps(display, ensure_ascii=False) if parsed is not None else display
                if isinstance(dump, str) and len(dump) > self.MAX_BYTES:
                    dump = dump[: self.MAX_BYTES] + '... (truncated)'

                # Log con nivel DEBUG
                logger.debug('Response body for %s %s -> status %s: %s', request.method, request.path, response.status_code, dump)
                # Además print directo para visibilidad en runserver
                try:
                    print(f"[DEBUG_RESPONSE] {request.method} {request.path} -> {response.status_code}: {dump}")
                except Exception:
                    pass
        except Exception as e:
            logger.exception('Error in DebugResponseBodyMiddleware: %s', e)
        return response
