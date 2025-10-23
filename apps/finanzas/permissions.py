from rest_framework.permissions import BasePermission


class IsInRole(BasePermission):
    """
    Permiso reutilizable que comprueba si el usuario tiene uno de los roles permitidos.

    La vista puede definir un atributo `allowed_roles = ['admin','junta']`.
    Si no existe `allowed_roles` se permite el acceso (no impone restricción adicional).
    Los usuarios con `is_staff` o `is_superuser` siempre pasan.
    """

    def has_permission(self, request, view):
        allowed = getattr(view, 'allowed_roles', None)
        user = getattr(request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return False

        # staff/superuser bypass
        if getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False):
            return True

        if allowed is None:
            return True

        return getattr(user, 'rol', None) in set(allowed)
