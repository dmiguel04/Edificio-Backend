# apps/finanzas/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    FinanzasViewSet,
    CreateCustomerAPIView,
    CreatePaymentIntentAPIView,
    PaymentListAPIView,
    PaymentDetailAPIView,
    ManualPaymentAPIView,
    GatewaysListAPIView,
    InvoicesListCreateAPIView,
    InvoiceDetailAPIView,
    InvoiceDownloadAPIView,
    OverdueChargeAPIView,
    PayrollListCreateAPIView,
    CheckoutSessionAPIView,
    SubscriptionCreateAPIView,
    ProductPriceAdminAPIView,
    ProductListAPIView,
    PriceListAPIView,
    RefundAPIView,
)
from .webhook import stripe_webhook

router = DefaultRouter()
router.register(r'finanzas', FinanzasViewSet, basename='finanzas')

urlpatterns = [
    path('', include(router.urls)),
    path('create-customer/', CreateCustomerAPIView.as_view(), name='finanzas-create-customer'),
    path('create-payment-intent/', CreatePaymentIntentAPIView.as_view(), name='finanzas-create-payment-intent'),
    path('payments/', PaymentListAPIView.as_view(), name='finanzas-payments'),
    path('payments/<int:pk>/', PaymentDetailAPIView.as_view(), name='finanzas-payments-detail'),
    # aliases expected by tests
    path('payments/list/', PaymentListAPIView.as_view(), name='finanzas-payments-list'),
    path('payments/manual/', ManualPaymentAPIView.as_view(), name='finanzas-payments-manual'),
    path('payments/manual/register/', ManualPaymentAPIView.as_view(), name='finanzas-register-manual'),
    path('gateways/', GatewaysListAPIView.as_view(), name='finanzas-gateways'),
    path('gateways/admin/', GatewaysListAPIView.as_view(), name='finanzas-gateway'),
    path('invoices/', InvoicesListCreateAPIView.as_view(), name='finanzas-invoices'),
    path('invoices/<int:pk>/', InvoiceDetailAPIView.as_view(), name='finanzas-invoice-detail'),
    path('invoices/<int:pk>/download/', InvoiceDownloadAPIView.as_view(), name='finanzas-invoice-download'),
    path('overdue/charge/', OverdueChargeAPIView.as_view(), name='finanzas-overdue-charge'),
    path('payroll/', PayrollListCreateAPIView.as_view(), name='finanzas-payroll'),
    path('create-checkout-session/', CheckoutSessionAPIView.as_view(), name='finanzas-create-checkout-session'),
    path('subscriptions/create/', SubscriptionCreateAPIView.as_view(), name='finanzas-subscriptions-create'),
    path('admin/product-price/', ProductPriceAdminAPIView.as_view(), name='finanzas-product-price-admin'),
    path('admin/products/', ProductListAPIView.as_view(), name='finanzas-products-list'),
    path('admin/prices/', PriceListAPIView.as_view(), name='finanzas-prices-list'),
    path('admin/refund/', RefundAPIView.as_view(), name='finanzas-refund'),
    path('webhooks/stripe/', stripe_webhook, name='finanzas-webhook'),
    path('webhooks/stripe/raw/', stripe_webhook, name='stripe-webhook'),
]