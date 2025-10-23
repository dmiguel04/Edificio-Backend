from rest_framework import serializers
from .models import StripeCustomer, Payment


class StripeCustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = StripeCustomer
        fields = ('id', 'usuario', 'stripe_customer_id', 'created_at')


class CreatePaymentSerializer(serializers.Serializer):
    amount = serializers.IntegerField(min_value=1)
    currency = serializers.CharField(max_length=8, default='usd')


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ('id', 'usuario', 'stripe_payment_intent', 'amount', 'currency', 'status', 'created_at', 'updated_at')


class PaymentSummarySerializer(serializers.ModelSerializer):
    """Serializer que oculta datos personales para la Junta (muestra solo cifras)."""
    class Meta:
        model = Payment
        # No exponer usuario ni stripe_payment_intent
        fields = ('id', 'amount', 'currency', 'status', 'created_at', 'updated_at')


class PayrollSerializer(serializers.ModelSerializer):
    class Meta:
        model = None  # placeholder: to be set dynamically in runtime to avoid circular import
        fields = ('id', 'name', 'period_start', 'period_end', 'total_amount', 'status', 'created_by', 'created_at')


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = None
        fields = ('id', 'usuario', 'amount', 'description', 'issued_at', 'due_date', 'paid', 'pdf_url')


class PaymentGatewaySerializer(serializers.ModelSerializer):
    class Meta:
        model = None
        fields = ('id', 'name', 'enabled', 'config', 'created_at')


class OverdueChargeSerializer(serializers.ModelSerializer):
    class Meta:
        model = None
        fields = ('id', 'usuario', 'invoice', 'amount', 'reason', 'applied_by', 'applied_at')

# Assign actual models to avoid circular import issues
from . import models as fin_models

PaymentSerializer.Meta.model = fin_models.Payment
PayrollSerializer.Meta.model = fin_models.Payroll
InvoiceSerializer.Meta.model = fin_models.Invoice
PaymentGatewaySerializer.Meta.model = fin_models.PaymentGateway
OverdueChargeSerializer.Meta.model = fin_models.OverdueCharge
