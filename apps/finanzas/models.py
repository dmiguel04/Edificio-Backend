from django.db import models
from django.conf import settings

class CuentaFinanciera(models.Model):
    usuario = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    stripe_account_id = models.CharField(max_length=255, blank=True, null=True)
    stripe_financial_account_id = models.CharField(max_length=255, blank=True, null=True)
    activa = models.BooleanField(default=False)
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Cuenta financiera de {self.usuario.email}"
    
class Tarjeta(models.Model):
    TIPOS_TARJETA = (
        ('virtual', 'Virtual'),
        ('physical', 'Física'),
    )
    
    ESTADOS_TARJETA = (
        ('active', 'Activa'),
        ('inactive', 'Inactiva'),
        ('canceled', 'Cancelada'),
        ('lost', 'Perdida'),
        ('stolen', 'Robada'),
    )
    
    cuenta_financiera = models.ForeignKey(CuentaFinanciera, on_delete=models.CASCADE, related_name='tarjetas')
    stripe_card_id = models.CharField(max_length=255)
    stripe_cardholder_id = models.CharField(max_length=255)
    tipo = models.CharField(max_length=20, choices=TIPOS_TARJETA, default='virtual')
    ultimos_digitos = models.CharField(max_length=4, blank=True, null=True)
    expiry_month = models.PositiveSmallIntegerField(null=True, blank=True)
    expiry_year = models.PositiveSmallIntegerField(null=True, blank=True)
    estado = models.CharField(max_length=20, choices=ESTADOS_TARJETA, default='active')
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Tarjeta **** {self.ultimos_digitos} - {self.get_tipo_display()}"


class CurrencyConversion(models.Model):
    """Registro de conversiones de moneda para reconciliación."""
    payment = models.ForeignKey('Payment', on_delete=models.SET_NULL, null=True, blank=True, related_name='conversions')
    original_amount = models.BigIntegerField()
    original_currency = models.CharField(max_length=8)
    converted_amount = models.BigIntegerField()
    target_currency = models.CharField(max_length=8)
    exchange_rate = models.DecimalField(max_digits=20, decimal_places=8)
    conversion_timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Conversion({self.original_amount} {self.original_currency} -> {self.converted_amount} {self.target_currency})"

class Transaccion(models.Model):
    TIPOS_TRANSACCION = (
        ('deposit', 'Depósito'),
        ('withdrawal', 'Retiro'),
        ('transfer_in', 'Transferencia entrante'),
        ('transfer_out', 'Transferencia saliente'),
        ('card_payment', 'Pago con tarjeta'),
    )
    
    ESTADOS_TRANSACCION = (
        ('pending', 'Pendiente'),
        ('succeeded', 'Completada'),
        ('failed', 'Fallida'),
        ('canceled', 'Cancelada'),
    )
    
    cuenta_financiera = models.ForeignKey(CuentaFinanciera, on_delete=models.CASCADE, related_name='transacciones')
    stripe_transaction_id = models.CharField(max_length=255)
    tipo = models.CharField(max_length=20, choices=TIPOS_TRANSACCION)
    monto = models.IntegerField()  # En centavos
    moneda = models.CharField(max_length=3, default='usd')
    estado = models.CharField(max_length=20, choices=ESTADOS_TRANSACCION, default='pending')
    descripcion = models.CharField(max_length=255, blank=True, null=True)
    tarjeta = models.ForeignKey(Tarjeta, on_delete=models.SET_NULL, null=True, blank=True)
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.get_tipo_display()} de {self.monto/100} {self.moneda.upper()}"


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
    support_ticket_id = models.CharField(max_length=128, blank=True, null=True)
    amount = models.PositiveIntegerField(help_text='Amount in cents')
    currency = models.CharField(max_length=8, default='usd')
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Payment({self.usuario}, {self.amount} {self.currency}, {self.status})"

    class Meta:
        indexes = [
            models.Index(fields=['stripe_payment_intent'], name='payment_intent_idx'),
            models.Index(fields=['status', 'created_at'], name='payment_status_date_idx'),
        ]


class WebhookEvent(models.Model):
    """Registro de eventos recibidos desde Stripe para idempotencia y auditoría."""
    event_id = models.CharField(max_length=128, unique=True)
    payload = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    processed = models.BooleanField(default=False)
    processed_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True, null=True, help_text='Último error ocurrido al procesar este webhook (si aplica)')

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
        """Genera un PDF con un QR y lo guarda en MEDIA_ROOT usando reportlab, qrcode y Pillow.
        Guarda la ruta pública en pdf_url (MEDIA_URL + path).
        """
        try:
            from django.core.files.storage import default_storage
            from django.core.files.base import ContentFile
            import io
            # Generar un QR con la información básica
            import qrcode
            from PIL import Image
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import A4

            qr_payload = f"invoice:{self.id}|user:{self.usuario.id}|amount:{self.amount}|currency:{self.currency}"
            qr = qrcode.QRCode(box_size=6, border=2)
            qr.add_data(qr_payload)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

            # Create an in-memory PDF
            buffer = io.BytesIO()
            p = canvas.Canvas(buffer, pagesize=A4)
            width, height = A4

            # Draw invoice text
            p.setFont('Helvetica-Bold', 14)
            p.drawString(50, height - 50, f"Factura #{self.id}")
            p.setFont('Helvetica', 12)
            p.drawString(50, height - 80, f"Usuario: {self.usuario.email}")
            p.drawString(50, height - 100, f"Monto: {self.amount/100:.2f} {self.currency.upper()}")
            p.drawString(50, height - 120, f"Descripcion: {self.description}")
            p.drawString(50, height - 140, f"Emitida: {self.issued_at.strftime('%Y-%m-%d %H:%M:%S')}")

            # Insert QR as temporary image
            qr_buffer = io.BytesIO()
            qr_img.save(qr_buffer, format='PNG')
            qr_buffer.seek(0)
            # reportlab requires PIL ImageFilename or BytesIO, use drawInlineImage
            p.drawInlineImage(qr_buffer, width - 200, height - 250, 150, 150)

            p.showPage()
            p.save()
            buffer.seek(0)

            filename = f"invoices/invoice_{self.id}.pdf"
            path = default_storage.save(filename, ContentFile(buffer.read()))
            self.pdf_url = getattr(settings, 'MEDIA_URL', '/media/') + path
            self.save()
            return self.pdf_url
        except Exception:
            # Fallback lightweight implementation (no reportlab/qrcode installed)
            try:
                from django.core.files.storage import default_storage
                from django.core.files.base import ContentFile
                content = f"Factura para {self.usuario.email}\nMonto: {self.amount/100} {self.currency}\nDescripcion: {self.description}".encode('utf-8')
                filename = f"invoices/invoice_{self.id}.txt"
                path = default_storage.save(filename, ContentFile(content))
                self.pdf_url = getattr(settings, 'MEDIA_URL', '/media/') + path
                self.save()
                return self.pdf_url
            except Exception:
                return ''


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


class Product(models.Model):
    """Local record of a Stripe Product."""
    stripe_product_id = models.CharField(max_length=128, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Product({self.name}, {self.stripe_product_id})"


class Price(models.Model):
    """Local record of a Stripe Price tied to a Product."""
    stripe_price_id = models.CharField(max_length=128, unique=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='prices')
    unit_amount = models.IntegerField()
    currency = models.CharField(max_length=8, default='usd')
    recurring = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Price({self.unit_amount} {self.currency}, {self.stripe_price_id})"


class Dispute(models.Model):
    """Registro de disputas/chargebacks provenientes de Stripe."""
    stripe_dispute_id = models.CharField(max_length=128, unique=True)
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, null=True, related_name='disputes')
    amount = models.PositiveIntegerField()
    reason = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Dispute({self.stripe_dispute_id}, status={self.status})"


class FinancialAuditLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    action_type = models.CharField(max_length=50)
    amount = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, null=True, blank=True)
    before_state = models.JSONField(null=True, blank=True)
    after_state = models.JSONField(null=True, blank=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"Audit({self.action_type}, {self.timestamp})"


class ComplianceLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    data_accessed = models.TextField()
    purpose = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"ComplianceLog({self.user}, {self.timestamp})"