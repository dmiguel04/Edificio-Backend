from django.core.management.base import BaseCommand
import logging

class Command(BaseCommand):
    help = 'Busca tarjetas que expiran pronto y notifica usuarios/administradores.'

    def handle(self, *args, **options):
        logger = logging.getLogger('finanzas.management.commands.check_expiring_cards')
        try:
            from apps.finanzas.utils import check_expiring_cards
            check_expiring_cards()
            logger.info('check_expiring_cards ejecutado correctamente')
        except Exception:
            logger.exception('Error ejecutando check_expiring_cards')
            raise
