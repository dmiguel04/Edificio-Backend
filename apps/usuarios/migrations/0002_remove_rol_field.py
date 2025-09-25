# Migración para eliminar campo 'rol' de Usuario
from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL(
            "ALTER TABLE usuarios_usuario DROP COLUMN IF EXISTS rol;",
            reverse_sql="ALTER TABLE usuarios_usuario ADD COLUMN rol VARCHAR(50);"
        ),
    ]