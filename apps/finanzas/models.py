from django.db import models
from django.conf import settings
from django.core.files.base import ContentFile
import qrcode
from io import BytesIO
from PIL import Image


class StripeCustomer(models.Model):
    usuario = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='stripe_customer')
    stripe_customer_id = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"StripeCustomer({self.usuario}, {self.stripe_customer_id})"


class Payment(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('succeeded', 'Succeeded'),
        ('failed', 'Failed'),
        ('requires_action', 'Requires action'),
    ]

    usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='payments')
    stripe_payment_intent = models.CharField(max_length=128, unique=True)
    amount = models.PositiveIntegerField(help_text='Amount in cents')
    currency = models.CharField(max_length=8, default='usd')
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Payment({self.usuario}, {self.amount} {self.currency}, {self.status})"


class WebhookEvent(models.Model):
    """Registro de eventos recibidos desde Stripe para idempotencia y auditoría."""
    event_id = models.CharField(max_length=128, unique=True)
    payload = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    processed = models.BooleanField(default=False)
    processed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"WebhookEvent({self.event_id}, processed={self.processed})"


class Payroll(models.Model):
    """Representa una nómina periódica que puede ser aprobada y ejecutada."""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('pending_approval', 'Pending approval'),
        ('approved', 'Approved'),
        ('executed', 'Executed'),
    ]

    name = models.CharField(max_length=128)
    period_start = models.DateField()
    period_end = models.DateField()
    total_amount = models.PositiveIntegerField(default=0, help_text='En centavos')
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_payrolls')
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default='draft')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payroll({self.name}, {self.period_start} - {self.period_end}, {self.status})"


class Invoice(models.Model):
    """Factura simple asociada a un residente."""
    usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='invoices')
    amount = models.PositiveIntegerField(help_text='En centavos')
    currency = models.CharField(max_length=8, default='usd')
    description = models.CharField(max_length=256, blank=True)
    issued_at = models.DateTimeField(auto_now_add=True)
    due_date = models.DateField(null=True, blank=True)
    paid = models.BooleanField(default=False)
    pdf_url = models.CharField(max_length=512, blank=True, help_text='URL temporal del PDF/QR (placeholder)')

    def __str__(self):
        return f"Invoice({self.usuario}, {self.amount}, paid={self.paid})"

    def generate_pdf_qr(self):
        """Genera un PDF con la factura y un QR embebido usando reportlab.

        Guarda el PDF en MEDIA_ROOT/invoices/ y actualiza `pdf_url`.
        """
        # Use the centralized PDF builder in apps.finanzas.pdf
        from .pdf import build_invoice_pdf_bytes
        import os

        pdf_bytes = build_invoice_pdf_bytes(self)

        media_dir = os.path.join(settings.MEDIA_ROOT, 'invoices')
        os.makedirs(media_dir, exist_ok=True)
        filename = f'invoice_{self.id}.pdf'
        path = os.path.join(media_dir, filename)

        with open(path, 'wb') as f:
            f.write(pdf_bytes)

        # Store relative url
        self.pdf_url = os.path.join(settings.MEDIA_URL, 'invoices', filename)
        self.save()
        return self.pdf_url


class PaymentGateway(models.Model):
    """Configuración de una pasarela de pago (p. ej. Stripe)"""
    name = models.CharField(max_length=64)
    enabled = models.BooleanField(default=False)
    config = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"PaymentGateway({self.name}, enabled={self.enabled})"


class OverdueCharge(models.Model):
    """Cargos/multas aplicados por morosidad."""
    usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, null=True, blank=True)
    amount = models.PositiveIntegerField(help_text='En centavos')
    reason = models.CharField(max_length=256, blank=True)
    applied_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='applied_charges')
    applied_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"OverdueCharge({self.usuario}, {self.amount})"
