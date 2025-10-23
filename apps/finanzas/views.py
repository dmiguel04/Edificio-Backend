from django.conf import settings
import time
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .permissions import IsInRole
from .models import StripeCustomer, Payment, WebhookEvent
from . import models as fin_models
from .serializers import StripeCustomerSerializer, CreatePaymentSerializer, PaymentSerializer
from .serializers import PaymentSummarySerializer
from .serializers import PayrollSerializer, InvoiceSerializer, PaymentGatewaySerializer, OverdueChargeSerializer
from django.contrib.auth import get_user_model
from apps.usuarios.models import AuditoriaEvento
class CreateStripeCustomerAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        # Si ya existe, devolver
        if hasattr(user, 'stripe_customer'):
            ser = StripeCustomerSerializer(user.stripe_customer)
            return Response(ser.data)
        # Crear customer en Stripe
        try:
            from .utils import create_stripe_customer
            customer = create_stripe_customer(email=user.email, name=str(user))
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        obj = StripeCustomer.objects.create(usuario=user, stripe_customer_id=customer['id'])
        ser = StripeCustomerSerializer(obj)
        return Response(ser.data, status=status.HTTP_201_CREATED)


class CreatePaymentIntentAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CreatePaymentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        user = request.user
        if not hasattr(user, 'stripe_customer'):
            return Response({'detail': 'Stripe customer not found. Create one first.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            from .utils import create_payment_intent
            intent = create_payment_intent(amount=data['amount'], currency=data.get('currency', 'usd'), customer_id=user.stripe_customer.stripe_customer_id)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        payment = Payment.objects.create(usuario=user, stripe_payment_intent=intent['id'], amount=data['amount'], currency=data.get('currency', 'usd'), status='pending')

        return Response({'client_secret': intent['client_secret'], 'payment_id': payment.id})


class PaymentListAPIView(APIView):
    """Listar pagos del usuario (o todos si es staff)."""
    # Authentication required; role-based visibility is decidida en el método GET
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # is_staff or roles admin/junta see all
        if user.is_staff or getattr(user, 'rol', None) in ('admin', 'junta'):
            qs = Payment.objects.all().order_by('-created_at')
        else:
            # Personal can see payments for the building (but not detailed personal data) - for now show all payments for user's building
            if getattr(user, 'rol', None) == 'personal':
                qs = Payment.objects.all().order_by('-created_at')
            else:
                qs = Payment.objects.filter(usuario=user).order_by('-created_at')
        # If the user is 'junta' or requests summary, return anonymized serializer
        summary_param = request.query_params.get('summary')
        if getattr(user, 'rol', None) == 'junta' or (summary_param and summary_param.lower() in ('1','true','yes')):
            ser = PaymentSummarySerializer(qs, many=True)
        else:
            ser = PaymentSerializer(qs, many=True)
        return Response(ser.data)


class PaymentDetailAPIView(APIView):
    """Detalle de un pago: sólo propietario o staff."""
    # Authentication required; detalle solo para propietario o roles admin/junta
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            payment = Payment.objects.get(pk=pk)
        except Payment.DoesNotExist:
            return Response({'detail': 'Not found.'}, status=404)

        if not (request.user.is_staff or payment.usuario == request.user or getattr(request.user, 'rol', None) in ('admin', 'junta')):
            return Response({'detail': 'Forbidden.'}, status=403)

        ser = PaymentSerializer(payment)
        return Response(ser.data)


@method_decorator(csrf_exempt, name='dispatch')
class StripeWebhookView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        payload = request.body
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
        webhook_secret = getattr(settings, 'STRIPE_WEBHOOK_SECRET', None)

        try:
            from .utils import construct_webhook_event
            event = construct_webhook_event(payload, sig_header, webhook_secret)
        except Exception:
            return Response(status=400)

        # Guardar evento (idempotencia)
        evt_id = event.get('id')
        if not evt_id:
            return Response(status=400)

        obj, created = WebhookEvent.objects.get_or_create(event_id=evt_id, defaults={'payload': event})
        if not created and obj.processed:
            # Ya procesado
            return Response({'status': 'already_processed'})

        # Procesar eventos relevantes
        if event['type'] == 'payment_intent.succeeded':
            pi = event['data']['object']
            pi_id = pi['id']
            Payment.objects.filter(stripe_payment_intent=pi_id).update(status='succeeded')

        if event['type'] in ('payment_intent.payment_failed', 'payment_intent.canceled'):
            pi = event['data']['object']
            pi_id = pi['id']
            Payment.objects.filter(stripe_payment_intent=pi_id).update(status='failed')

        # marcar procesado
        obj.processed = True
        from django.utils import timezone
        obj.processed_at = timezone.now()
        obj.save()

        return Response({'status': 'ok'})


class RegistroPagoManualAPIView(APIView):
    """Permite al personal o admin registrar un pago manual (efectivo/cheque) para un residente."""
    permission_classes = [IsAuthenticated, IsInRole]
    allowed_roles = ['personal', 'admin']

    def post(self, request):
        # Esperamos: usuario_id (id del usuario residente), amount, currency, metodo ('efectivo'|'cheque')
        data = request.data
        usuario_id = data.get('usuario_id')
        amount = data.get('amount')
        currency = data.get('currency', 'usd')
        metodo = data.get('metodo', 'efectivo')

        if not usuario_id or not amount:
            return Response({'detail': 'usuario_id and amount are required.'}, status=400)

        # Validaciones: limites máximos
        try:
            amount_int = int(amount)
        except Exception:
            return Response({'detail': 'amount must be an integer (in cents).'}, status=400)

        from django.conf import settings as dj_settings
        if amount_int <= 0 or amount_int > dj_settings.MAX_MANUAL_PAYMENT_AMOUNT:
            return Response({'detail': 'amount out of allowed range.'}, status=400)

        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            usuario = User.objects.get(pk=usuario_id)
        except Exception:
            return Response({'detail': 'Usuario no encontrado.'}, status=404)

        # Crear Payment local sin interacción con Stripe (registro manual)
        payment = Payment.objects.create(usuario=usuario, stripe_payment_intent=f'manual-{usuario_id}-{int(amount)}-{int(time.time())}', amount=int(amount), currency=currency, status='succeeded')

        ser = PaymentSerializer(payment)

        # Registrar auditoría
        try:
            AuditoriaEvento.objects.create(usuario=request.user, username=request.user.username, evento='reset_password', detalle=f'Pago manual registrado para usuario {usuario_id}: {amount} {currency}')
        except Exception:
            pass

        return Response(ser.data, status=201)


class PayrollAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Crear nómina (personal puede crear draft; admin/junta pueden cambiar estados)
        data = request.data
        name = data.get('name')
        period_start = data.get('period_start')
        period_end = data.get('period_end')
        total_amount = data.get('total_amount', 0)
        if not name or not period_start or not period_end:
            return Response({'detail': 'name, period_start and period_end required.'}, status=400)

        payroll = fin_models.Payroll.objects.create(name=name, period_start=period_start, period_end=period_end, total_amount=total_amount, created_by=request.user)
        ser = PayrollSerializer(payroll)
        return Response(ser.data, status=201)


class PayrollApproveAPIView(APIView):
    permission_classes = [IsAuthenticated, IsInRole]
    allowed_roles = ['junta']

    def post(self, request, pk):
        try:
            payroll = fin_models.Payroll.objects.get(pk=pk)
        except fin_models.Payroll.DoesNotExist:
            return Response({'detail': 'Not found.'}, status=404)

        if payroll.status != 'pending_approval':
            return Response({'detail': 'Payroll not pending approval.'}, status=400)

        payroll.status = 'approved'
        payroll.save()
        AuditoriaEvento.objects.create(usuario=request.user, username=request.user.username, evento='cambio_password', detalle=f'Payroll {pk} approved')
        return Response({'status': 'approved'})


class PayrollExecuteAPIView(APIView):
    permission_classes = [IsAuthenticated, IsInRole]
    allowed_roles = ['admin']

    def post(self, request, pk):
        try:
            payroll = fin_models.Payroll.objects.get(pk=pk)
        except fin_models.Payroll.DoesNotExist:
            return Response({'detail': 'Not found.'}, status=404)

        if payroll.status != 'approved':
            return Response({'detail': 'Payroll not approved.'}, status=400)

        payroll.status = 'executed'
        payroll.save()
        AuditoriaEvento.objects.create(usuario=request.user, username=request.user.username, evento='cambio_password', detalle=f'Payroll {pk} executed')
        return Response({'status': 'executed'})


class InvoiceAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        usuario_id = data.get('usuario_id')
        amount = data.get('amount')
        desc = data.get('description', '')
        if not usuario_id or not amount:
            return Response({'detail': 'usuario_id and amount required.'}, status=400)
        try:
            User = get_user_model()
            usuario = User.objects.get(pk=usuario_id)
        except Exception:
            return Response({'detail': 'Usuario no encontrado.'}, status=404)

        inv = fin_models.Invoice.objects.create(usuario=usuario, amount=amount, description=desc)
        AuditoriaEvento.objects.create(usuario=request.user, username=request.user.username, evento='reset_password', detalle=f'Invoice {inv.id} created for {usuario_id}')
        ser = InvoiceSerializer(inv)
        return Response(ser.data, status=201)


class PaymentGatewayAPIView(APIView):
    permission_classes = [IsAuthenticated, IsInRole]
    allowed_roles = ['admin']

    def get(self, request):
        qs = fin_models.PaymentGateway.objects.all()
        ser = PaymentGatewaySerializer(qs, many=True)
        return Response(ser.data)

    def post(self, request):
        data = request.data
        name = data.get('name')
        config = data.get('config', {})
        enabled = data.get('enabled', False)
        gw = fin_models.PaymentGateway.objects.create(name=name, config=config, enabled=enabled)
        AuditoriaEvento.objects.create(usuario=request.user, username=request.user.username, evento='reset_password', detalle=f'Payment gateway {name} created')
        ser = PaymentGatewaySerializer(gw)
        return Response(ser.data, status=201)


class OverdueChargeAPIView(APIView):
    permission_classes = [IsAuthenticated, IsInRole]
    allowed_roles = ['admin']

    def post(self, request):
        data = request.data
        usuario_id = data.get('usuario_id')
        amount = data.get('amount')
        reason = data.get('reason', '')
        if not usuario_id or not amount:
            return Response({'detail': 'usuario_id and amount required.'}, status=400)
        try:
            User = get_user_model()
            usuario = User.objects.get(pk=usuario_id)
        except Exception:
            return Response({'detail': 'Usuario no encontrado.'}, status=404)

        try:
            amount_int = int(amount)
        except Exception:
            return Response({'detail': 'amount must be an integer (in cents).'}, status=400)

        from django.conf import settings as dj_settings
        if amount_int <= 0 or amount_int > dj_settings.MAX_OVERDUE_CHARGE_AMOUNT:
            return Response({'detail': 'amount out of allowed range.'}, status=400)

        charge = fin_models.OverdueCharge.objects.create(usuario=usuario, amount=amount_int, reason=reason, applied_by=request.user)
        AuditoriaEvento.objects.create(usuario=request.user, username=request.user.username, evento='acceso_no_autorizado', detalle=f'Applied overdue charge {charge.id} to {usuario_id}')
        ser = OverdueChargeSerializer(charge)
        return Response(ser.data, status=201)


class InvoiceVerifyView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        # token in query param 't'
        t = request.query_params.get('t')
        if not t:
            return Response({'detail': 'token required as query param t'}, status=400)

        import base64, json, hmac, hashlib
        try:
            raw = base64.urlsafe_b64decode(t.encode())
            obj = json.loads(raw)
        except Exception:
            return Response({'detail': 'invalid token'}, status=400)

        sig = obj.pop('sig', None)
        key = getattr(settings, 'INVOICE_SIGNING_KEY', None)
        if key and sig:
            payload = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
            expected = hmac.new(key.encode('utf-8'), payload, hashlib.sha256).hexdigest()
            from django.utils.crypto import constant_time_compare
            if not constant_time_compare(expected, sig):
                return Response({'detail': 'invalid signature'}, status=400)

        # expect id like inv_5
        inv_id = obj.get('id')
        if not inv_id or not inv_id.startswith('inv_'):
            return Response({'detail': 'invalid id'}, status=400)

        try:
            invoice_pk = int(inv_id.split('_', 1)[1])
        except Exception:
            return Response({'detail': 'invalid id'}, status=400)

        try:
            inv = fin_models.Invoice.objects.get(pk=invoice_pk)
        except fin_models.Invoice.DoesNotExist:
            return Response({'detail': 'invoice not found'}, status=404)

        # If in DEBUG, redirect to media URL; otherwise return a JSON with download token or redirect to a protected endpoint
        if settings.DEBUG:
            from django.shortcuts import redirect
            return redirect(inv.pdf_url)
        else:
            # production: return JSON with a note (or implement presigned URL logic)
            return Response({'detail': 'ok', 'invoice_id': inv.id, 'pdf_url': inv.pdf_url})
