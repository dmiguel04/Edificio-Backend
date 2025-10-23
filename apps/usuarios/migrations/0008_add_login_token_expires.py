from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0007_alter_auditoriaevento_evento'),
    ]

    operations = [
        migrations.RunSQL(
            sql=("UPDATE usuarios_usuario SET login_token = substring(login_token from 1 for 16) "
                 "WHERE login_token IS NOT NULL;"),
            reverse_sql=migrations.RunSQL.noop,
        ),
        migrations.AlterField(
            model_name='usuario',
            name='login_token',
            field=models.CharField(max_length=16, null=True, blank=True),
        ),
        migrations.AddField(
            model_name='usuario',
            name='login_token_expires',
            field=models.DateTimeField(null=True, blank=True),
        ),
    ]
