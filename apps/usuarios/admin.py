from django.contrib import admin

from .models import AuditoriaEvento
from .models import Usuario
from django.contrib.auth.admin import UserAdmin


@admin.register(Usuario)
class UsuarioAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('persona', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Perfil', {'fields': ('rol', 'telefono', 'apartamento', 'activo')}),
    )
    list_display = ('username', 'email', 'rol', 'is_staff', 'is_active')

@admin.register(AuditoriaEvento)
class AuditoriaEventoAdmin(admin.ModelAdmin):
    list_display = ('evento', 'username', 'ip', 'fecha', 'detalle')
    search_fields = ('username', 'evento', 'detalle')
    list_filter = ('evento', 'fecha')
