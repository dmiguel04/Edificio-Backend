"""Modelos auxiliares para el módulo de gestión de usuarios.

Este módulo no define un modelo Usuario propio; usa el modelo central
`apps.usuarios.Usuario` definido en la app usuarios.
"""

from django.db import models


class Nota(models.Model):
    texto = models.TextField()
    creado = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.texto[:50]