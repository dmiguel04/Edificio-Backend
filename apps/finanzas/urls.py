from django.urls import path
from .views import CreateStripeCustomerAPIView, CreatePaymentIntentAPIView, StripeWebhookView, PaymentListAPIView, PaymentDetailAPIView
from .views import RegistroPagoManualAPIView, PaymentGatewayAPIView, InvoiceAPIView, OverdueChargeAPIView, PayrollAPIView, PayrollApproveAPIView, PayrollExecuteAPIView
from .views import InvoiceVerifyView

urlpatterns = [
    path('create-customer/', CreateStripeCustomerAPIView.as_view(), name='finanzas-create-customer'),
    path('create-payment-intent/', CreatePaymentIntentAPIView.as_view(), name='finanzas-create-payment-intent'),
    path('webhook/', StripeWebhookView.as_view(), name='finanzas-webhook'),
    path('payments/', PaymentListAPIView.as_view(), name='finanzas-payments-list'),
    path('payments/<int:pk>/', PaymentDetailAPIView.as_view(), name='finanzas-payments-detail'),
    path('payments/manual/', RegistroPagoManualAPIView.as_view(), name='finanzas-register-manual'),
    path('gateways/', PaymentGatewayAPIView.as_view(), name='finanzas-gateway'),
    path('invoices/', InvoiceAPIView.as_view(), name='finanzas-invoice'),
    path('invoices/verify/', InvoiceVerifyView.as_view(), name='finanzas-invoice-verify'),
    path('overdue/charge/', OverdueChargeAPIView.as_view(), name='finanzas-overdue-charge'),
    path('payroll/', PayrollAPIView.as_view(), name='finanzas-payroll'),
    path('payroll/<int:pk>/approve/', PayrollApproveAPIView.as_view(), name='finanzas-payroll-approve'),
    path('payroll/<int:pk>/execute/', PayrollExecuteAPIView.as_view(), name='finanzas-payroll-execute'),
]
