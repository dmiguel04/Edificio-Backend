from django.contrib import admin
from . import models


@admin.register(models.PaymentGateway)
class PaymentGatewayAdmin(admin.ModelAdmin):
    list_display = ('name', 'enabled', 'created_at')
    readonly_fields = ('created_at',)

    def get_readonly_fields(self, request, obj=None):
        # Hide config from non-superusers
        if not request.user.is_superuser:
            return self.readonly_fields + ('config',)
        return self.readonly_fields


@admin.register(models.Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = ('id', 'usuario', 'amount', 'paid', 'issued_at')
    readonly_fields = ('issued_at',)
from django.contrib import admin
from .models import StripeCustomer, Payment


@admin.register(StripeCustomer)
class StripeCustomerAdmin(admin.ModelAdmin):
    list_display = ('usuario', 'stripe_customer_id', 'created_at')


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('usuario', 'stripe_payment_intent', 'amount', 'currency', 'status', 'created_at')
    list_filter = ('status', 'currency')
