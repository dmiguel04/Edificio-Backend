from rest_framework import permissions


class IsAdministrador(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and getattr(request.user, 'rol', None) == 'admin')


class IsJunta(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and getattr(request.user, 'rol', None) == 'junta')


class IsPersonal(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and getattr(request.user, 'rol', None) == 'personal')


class IsResidente(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and getattr(request.user, 'rol', None) == 'residente')


class AdminOrSelf(permissions.BasePermission):
    """Permite si es admin o es el mismo usuario"""
    def has_object_permission(self, request, view, obj):
        if request.user and getattr(request.user, 'rol', None) == 'admin':
            return True
        return obj == request.user
