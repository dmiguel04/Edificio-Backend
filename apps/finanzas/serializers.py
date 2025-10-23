from rest_framework import serializers
from .models import CuentaFinanciera, Tarjeta, Transaccion, StripeCustomer, Payment, Invoice, PaymentGateway, OverdueCharge, Payroll


class CuentaFinancieraSerializer(serializers.ModelSerializer):
    class Meta:
        model = CuentaFinanciera
        fields = ['id', 'usuario', 'stripe_account_id', 'stripe_financial_account_id', 'activa', 'fecha_creacion']
        read_only_fields = ['stripe_account_id', 'stripe_financial_account_id', 'activa', 'fecha_creacion']


class TarjetaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tarjeta
        fields = ['id', 'cuenta_financiera', 'tipo', 'ultimos_digitos', 'estado', 'fecha_creacion']
        read_only_fields = ['ultimos_digitos', 'estado', 'fecha_creacion']


class TransaccionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaccion
        fields = ['id', 'cuenta_financiera', 'stripe_transaction_id', 'tipo', 'monto', 'moneda', 'estado', 'descripcion', 'tarjeta', 'fecha_creacion']
        read_only_fields = ['estado', 'fecha_creacion']


class CrearTarjetaSerializer(serializers.Serializer):
    tipo = serializers.ChoiceField(choices=[('virtual','virtual'),('physical','physical')])


class TransferirFondosSerializer(serializers.Serializer):
    amount = serializers.IntegerField(min_value=1)
    currency = serializers.CharField(max_length=8, default='usd', required=False)
    destination_account_id = serializers.CharField(required=True)


class CreateCustomerSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    name = serializers.CharField(required=False, allow_blank=True)


class CreatePaymentIntentSerializer(serializers.Serializer):
    amount = serializers.IntegerField(min_value=1)
    currency = serializers.CharField(max_length=8, default='usd', required=False)
    customer_id = serializers.CharField(required=False, allow_blank=True)


class CheckoutLineItemSerializer(serializers.Serializer):
    price_data = serializers.DictField()
    quantity = serializers.IntegerField(min_value=1, default=1)


class CreateCheckoutSessionSerializer(serializers.Serializer):
    line_items = serializers.ListField(child=CheckoutLineItemSerializer())
    success_url = serializers.URLField()
    cancel_url = serializers.URLField()


class CreateSubscriptionSerializer(serializers.Serializer):
    price_id = serializers.CharField()


class ProductCreateSerializer(serializers.Serializer):
    name = serializers.CharField()
    description = serializers.CharField(required=False, allow_blank=True)


class PriceCreateSerializer(serializers.Serializer):
    product_id = serializers.CharField()
    unit_amount = serializers.IntegerField(min_value=1)
    currency = serializers.CharField(max_length=8, default='usd')
    recurring = serializers.DictField(required=False)


class ProductModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = 'finanzas.Product'
        fields = ['id', 'stripe_product_id', 'name', 'description', 'created_at']


class PriceModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = 'finanzas.Price'
        fields = ['id', 'stripe_price_id', 'product', 'unit_amount', 'currency', 'recurring', 'created_at']


class ManualPaymentSerializer(serializers.Serializer):
    amount = serializers.IntegerField(min_value=1)
    currency = serializers.CharField(max_length=8, default='usd', required=False)
    reference = serializers.CharField(required=False, allow_blank=True)


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['id', 'usuario', 'stripe_payment_intent', 'amount', 'currency', 'status', 'created_at', 'updated_at']
        read_only_fields = ['status', 'created_at', 'updated_at']


class PaymentGatewaySerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentGateway
        fields = ['id', 'name', 'enabled', 'config', 'created_at']
        read_only_fields = ['created_at']


class InvoiceCreateSerializer(serializers.Serializer):
    usuario_id = serializers.IntegerField(required=False)
    amount = serializers.IntegerField(min_value=1)
    currency = serializers.CharField(max_length=8, default='usd', required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    due_date = serializers.DateField(required=False)


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ['id', 'usuario', 'amount', 'currency', 'description', 'issued_at', 'due_date', 'paid', 'pdf_url']
        read_only_fields = ['issued_at', 'pdf_url']


class OverdueChargeSerializer(serializers.Serializer):
    usuario_id = serializers.IntegerField()
    invoice_id = serializers.IntegerField(required=False)
    amount = serializers.IntegerField(min_value=1)
    reason = serializers.CharField(required=False, allow_blank=True)


class PayrollSerializer(serializers.Serializer):
    name = serializers.CharField()
    period_start = serializers.DateField()
    period_end = serializers.DateField()
    total_amount = serializers.IntegerField(min_value=0, required=False)
