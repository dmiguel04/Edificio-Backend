from django.contrib import admin

from .models import AuditoriaEvento

@admin.register(AuditoriaEvento)
class AuditoriaEventoAdmin(admin.ModelAdmin):
    list_display = ('evento', 'username', 'ip', 'fecha', 'detalle')
    search_fields = ('username', 'evento', 'detalle')
    list_filter = ('evento', 'fecha')
