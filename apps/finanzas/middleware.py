from django.http import JsonResponse

class FinanzasPermissionMiddleware:
    """Simple middleware that can block non-staff users from accessing URLs under /api/finanzas/admin/ or other sensitive paths.

    Configure in settings.MIDDLEWARE if you want this active.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if path.startswith('/api/finanzas/admin/'):
            user = getattr(request, 'user', None)
            if not (user and user.is_authenticated and user.is_staff):
                return JsonResponse({'error': 'sin permiso'}, status=403)
        return self.get_response(request)
