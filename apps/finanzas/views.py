# apps/finanzas/views.py
import time
from django.conf import settings
try:
    import stripe
    stripe.api_key = settings.STRIPE_SECRET_KEY
except Exception:
    stripe = None
from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import (
    CuentaFinanciera, Tarjeta, Transaccion,
    StripeCustomer, Payment, Invoice, PaymentGateway, OverdueCharge, Payroll
)
from .serializers import (
    CuentaFinancieraSerializer,
    TarjetaSerializer,
    TransaccionSerializer,
    CrearTarjetaSerializer,
    TransferirFondosSerializer,
    CreateCustomerSerializer,
    CreatePaymentIntentSerializer,
    ManualPaymentSerializer,
    PaymentSerializer,
    PaymentGatewaySerializer,
    InvoiceCreateSerializer,
    InvoiceSerializer,
    OverdueChargeSerializer,
    PayrollSerializer,
    ProductCreateSerializer,
    PriceCreateSerializer,
    ProductModelSerializer,
    PriceModelSerializer,
)
from . import utils as fin_utils
from django.core.mail import send_mail
import logging
from django.shortcuts import get_object_or_404
from django.http import FileResponse, Http404
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.utils import timezone
import os
from django.conf import settings

class FinanzasViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['post'])
    def crear_cuenta_financiera(self, request):
        usuario = request.user
        
        # Verificar si ya tiene cuenta financiera
        if hasattr(usuario, 'cuentafinanciera'):
            return Response(
                {"error": "El usuario ya tiene una cuenta financiera"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if stripe is None:
            return Response({'error': 'stripe library no instalado'}, status=status.HTTP_501_NOT_IMPLEMENTED)

        try:
            # Crear cuenta conectada en Stripe
            account = stripe.Account.create(
                type='custom',
                country='US',
                email=usuario.email,
                business_type='individual',
                individual={
                    'first_name': usuario.first_name,
                    'last_name': usuario.last_name,
                    'email': usuario.email,
                },
                capabilities={
                    'card_payments': {'requested': True},
                    'transfers': {'requested': True},
                    'treasury': {'requested': True},
                },
                tos_acceptance={
                    'date': int(time.time()),
                    'ip': request.META.get('REMOTE_ADDR', '127.0.0.1'),
                }
            )
            
            # Crear cuenta financiera en Stripe
            financial_account = stripe.treasury.FinancialAccount.create(
                supported_currencies=['usd'],
                features={
                    'card_issuing': {'requested': True},
                    'deposit_insurance': {'requested': True},
                    'financial_addresses': {'aba': {'requested': True}}
                },
                stripe_account=account.id
            )
            
            # Guardar en nuestra base de datos
            cuenta_financiera = CuentaFinanciera.objects.create(
                usuario=usuario,
                stripe_account_id=account.id,
                stripe_financial_account_id=financial_account.id,
                activa=True
            )
            
            serializer = CuentaFinancieraSerializer(cuenta_financiera)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'])
    def crear_tarjeta(self, request):
        serializer = CrearTarjetaSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        usuario = request.user
        
        if stripe is None:
            return Response({'error': 'stripe library no instalado'}, status=status.HTTP_501_NOT_IMPLEMENTED)

        try:
            # Verificar si el usuario tiene cuenta financiera
            cuenta_financiera = CuentaFinanciera.objects.get(usuario=usuario)
            
            # Crear cardholder en Stripe
            cardholder = stripe.issuing.Cardholder.create(
                type='individual',
                name=f"{usuario.first_name} {usuario.last_name}",
                email=usuario.email,
                status='active',
                stripe_account=cuenta_financiera.stripe_account_id
            )
            
            # Crear tarjeta en Stripe
            card = stripe.issuing.Card.create(
                cardholder=cardholder.id,
                currency='usd',
                type=serializer.validated_data['tipo'],
                status='active',
                financial_account=cuenta_financiera.stripe_financial_account_id,
                stripe_account=cuenta_financiera.stripe_account_id
            )
            
            # Guardar en nuestra base de datos
            tarjeta = Tarjeta.objects.create(
                cuenta_financiera=cuenta_financiera,
                stripe_card_id=card.id,
                stripe_cardholder_id=cardholder.id,
                tipo=serializer.validated_data['tipo'],
                ultimos_digitos=card.last4
            )
            
            return Response(TarjetaSerializer(tarjeta).data, status=status.HTTP_201_CREATED)
            
        except CuentaFinanciera.DoesNotExist:
            return Response(
                {"error": "El usuario no tiene una cuenta financiera activa"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['get'])
    def obtener_saldo(self, request):
        usuario = request.user
        
        if stripe is None:
            return Response({'error': 'stripe library no instalado'}, status=status.HTTP_501_NOT_IMPLEMENTED)

        try:
            # Verificar si el usuario tiene cuenta financiera
            cuenta_financiera = CuentaFinanciera.objects.get(usuario=usuario)
            
            # Obtener saldo de Stripe
            financial_account = stripe.treasury.FinancialAccount.retrieve(
                cuenta_financiera.stripe_financial_account_id,
                stripe_account=cuenta_financiera.stripe_account_id
            )
            
            return Response({
                "balance": financial_account.balance.available,
                "currency": financial_account.balance.currency
            })
            
        except CuentaFinanciera.DoesNotExist:
            return Response(
                {"error": "El usuario no tiene una cuenta financiera activa"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['post'])
    def transferir_fondos(self, request):
        serializer = TransferirFondosSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        usuario = request.user
        
        if stripe is None:
            return Response({'error': 'stripe library no instalado'}, status=status.HTTP_501_NOT_IMPLEMENTED)

        try:
            # Verificar si el usuario tiene cuenta financiera
            cuenta_financiera = CuentaFinanciera.objects.get(usuario=usuario)
            
            # Crear transferencia en Stripe
            outbound_transfer = stripe.treasury.OutboundTransfer.create(
                financial_account=cuenta_financiera.stripe_financial_account_id,
                destination_payment_method=serializer.validated_data['destination_payment_method'],
                amount=serializer.validated_data['monto'],
                currency='usd',
                description=serializer.validated_data.get('descripcion', 'Transferencia saliente'),
                stripe_account=cuenta_financiera.stripe_account_id
            )
            
            # Registrar la transacción
            transaccion = Transaccion.objects.create(
                cuenta_financiera=cuenta_financiera,
                stripe_transaction_id=outbound_transfer.id,
                tipo='transfer_out',
                monto=serializer.validated_data['monto'],
                moneda='usd',
                estado=outbound_transfer.status,
                descripcion=serializer.validated_data.get('descripcion', 'Transferencia saliente')
            )
            
            return Response(TransaccionSerializer(transaccion).data)
            
        except CuentaFinanciera.DoesNotExist:
            return Response(
                {"error": "El usuario no tiene una cuenta financiera activa"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    @action(detail=False, methods=['get'])
    def listar_transacciones(self, request):
        usuario = request.user
        
        try:
            # Verificar si el usuario tiene cuenta financiera
            cuenta_financiera = CuentaFinanciera.objects.get(usuario=usuario)
            
            # Obtener transacciones de Stripe
            transactions = stripe.treasury.Transaction.list(
                financial_account=cuenta_financiera.stripe_financial_account_id,
                limit=20,
                stripe_account=cuenta_financiera.stripe_account_id
            )
            
            # Sincronizar con nuestra base de datos
            for transaction in transactions.data:
                # Verificar si ya existe
                if not Transaccion.objects.filter(stripe_transaction_id=transaction.id).exists():
                    # Determinar el tipo de transacción
                    tipo = 'deposit'
                    if transaction.flow == 'outbound':
                        tipo = 'transfer_out'
                    elif transaction.flow == 'inbound':
                        tipo = 'transfer_in'
                    
                    Transaccion.objects.create(
                        cuenta_financiera=cuenta_financiera,
                        stripe_transaction_id=transaction.id,
                        tipo=tipo,
                        monto=transaction.amount,
                        moneda=transaction.currency,
                        estado='succeeded',
                        descripcion=transaction.description
                    )
            
            # Obtener transacciones actualizadas
            transacciones = Transaccion.objects.filter(cuenta_financiera=cuenta_financiera).order_by('-fecha_creacion')[:20]
            
            return Response(TransaccionSerializer(transacciones, many=True).data)
            
        except CuentaFinanciera.DoesNotExist:
            return Response(
                {"error": "El usuario no tiene una cuenta financiera activa"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


# --- Endpoints adicionales solicitados ---


class CreateCustomerAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CreateCustomerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email') or getattr(request.user, 'email', None)
        name = serializer.validated_data.get('name') or (f"{getattr(request.user, 'persona', None) and request.user.persona.nombre or ''} {getattr(request.user, 'persona', None) and request.user.persona.apellido or ''}".strip())
        if not email:
            return Response({'error': 'email requerido'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            customer = fin_utils.create_stripe_customer(email=email, name=name)
            StripeCustomer.objects.update_or_create(usuario=request.user, defaults={'stripe_customer_id': customer['id']})
            return Response({'stripe_customer_id': customer['id']}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CreatePaymentIntentAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        # Allow unauthenticated requests in DEBUG for local development convenience.
        if getattr(settings, 'DEBUG', False):
            return [AllowAny()]
        return [IsAuthenticated()]

    def post(self, request):
        serializer = CreatePaymentIntentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        amount = serializer.validated_data['amount']
        currency = serializer.validated_data.get('currency', 'usd')
        customer_id = serializer.validated_data.get('customer_id')
        # si no hay customer_id, comprobar si usuario tiene StripeCustomer registrado
        user_obj = request.user
        if not customer_id:
            if getattr(request, 'user', None) and getattr(request.user, 'is_authenticated', False):
                if not hasattr(request.user, 'stripe_customer'):
                    return Response({'error': 'stripe customer no encontrado'}, status=status.HTTP_400_BAD_REQUEST)
                customer_id = request.user.stripe_customer.stripe_customer_id
            else:
                # In DEBUG, allow anonymous/dev requests: create or use a dev user to attach Payment records
                if getattr(settings, 'DEBUG', False):
                    from django.contrib.auth import get_user_model
                    User = get_user_model()
                    dev_username = getattr(settings, 'DEV_STRIPE_USER', 'dev_stripe_user')
                    dev_email = getattr(settings, 'DEV_STRIPE_EMAIL', 'dev@localhost')
                    try:
                        user_obj, created = User.objects.get_or_create(username=dev_username, defaults={'email': dev_email})
                        if created:
                            try:
                                user_obj.set_password('devpass')
                                user_obj.save()
                            except Exception:
                                pass
                    except Exception:
                        user_obj = None
                    # do not require a stripe_customer for dev flow; customer_id can be None
                else:
                    return Response({'error': 'stripe customer no encontrado'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # create internal Payment record first so we can reconcile later
            payment_user = user_obj if user_obj is not None else request.user
            payment = Payment.objects.create(usuario=payment_user, stripe_payment_intent='', amount=int(amount), currency=currency, status='pending')
            pm_types = request.data.get('payment_method_types')
            # allow passthrough extras like confirm, return_url
            extras = {}
            if 'confirm' in request.data:
                extras['confirm'] = bool(request.data.get('confirm'))
            if 'return_url' in request.data:
                extras['return_url'] = request.data.get('return_url')
            # include any other extras explicitly allowed
            allowed_extras = ['payment_method_options', 'setup_future_usage']
            for k in allowed_extras:
                if k in request.data:
                    extras[k] = request.data.get(k)

            intent = fin_utils.create_payment_intent_with_metadata(int(amount), currency, customer_id, metadata={'payment_id': str(payment.id)}, payment_method_types=pm_types, **extras)
            # store the returned intent id
            payment.stripe_payment_intent = intent.get('id')
            payment.status = intent.get('status', 'pending')
            payment.save()
            # Build response: include client_secret, id, payment_id and next_action & raw intent for debugging
            resp = {'client_secret': intent.get('client_secret'), 'id': intent.get('id'), 'payment_id': payment.id}
            if intent.get('next_action'):
                resp['next_action'] = intent.get('next_action')
            # include minimal intent object for frontend debug if running in DEBUG
            if getattr(settings, 'DEBUG', False):
                # convert stripe object to dict safely
                try:
                    resp['payment_intent'] = dict(intent)
                except Exception:
                    resp['payment_intent'] = intent
            return Response(resp)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CheckoutSessionAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if getattr(settings, 'DEBUG', False):
            return [AllowAny()]
        return [IsAuthenticated()]

    def post(self, request):
        # expected payload: items (list of {price_data: {currency, product_data: {name, images}, unit_amount}, quantity}), success_url, cancel_url
        data = request.data
        items = data.get('line_items')
        success_url = data.get('success_url')
        cancel_url = data.get('cancel_url')
        if not items or not success_url or not cancel_url:
            return Response({'error': 'line_items, success_url y cancel_url requeridos'}, status=status.HTTP_400_BAD_REQUEST)
        customer_id = None
        user_obj = request.user
        if getattr(request, 'user', None) and getattr(request.user, 'is_authenticated', False):
            if hasattr(request.user, 'stripe_customer'):
                customer_id = request.user.stripe_customer.stripe_customer_id
        else:
            # allow anonymous/dev requests in DEBUG: use dev user
            if getattr(settings, 'DEBUG', False):
                from django.contrib.auth import get_user_model
                User = get_user_model()
                dev_username = getattr(settings, 'DEV_STRIPE_USER', 'dev_stripe_user')
                dev_email = getattr(settings, 'DEV_STRIPE_EMAIL', 'dev@localhost')
                try:
                    user_obj, created = User.objects.get_or_create(username=dev_username, defaults={'email': dev_email})
                    if created:
                        try:
                            user_obj.set_password('devpass')
                            user_obj.save()
                        except Exception:
                            pass
                except Exception:
                    user_obj = None
        # optional: frontend can request a PaymentIntent instead of Checkout Session
        create_pi = data.get('create_payment_intent', False)
        if create_pi:
            # expected: amount (int cents) and currency
            amount = data.get('amount')
            currency = data.get('currency', 'usd')
            if not amount:
                return Response({'error': 'amount requerido para create_payment_intent'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                # create internal Payment record first so we can reconcile later
                payment = Payment.objects.create(usuario=request.user, stripe_payment_intent='', amount=int(amount), currency=currency, status='pending')
                pm_types = data.get('payment_method_types')
                intent = fin_utils.create_payment_intent_with_metadata(int(amount), currency, customer_id, metadata={'payment_id': str(payment.id)}, payment_method_types=pm_types)
                payment.stripe_payment_intent = intent.get('id')
                payment.status = intent.get('status', 'pending')
                payment.save()
                resp = {'client_secret': intent.get('client_secret'), 'id': intent.get('id'), 'payment_id': payment.id}
                if intent.get('next_action'):
                    resp['next_action'] = intent.get('next_action')
                return Response(resp)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            session = fin_utils.create_checkout_session(line_items=items, success_url=success_url, cancel_url=cancel_url, customer=customer_id)
            return Response({'url': session.url, 'id': session.id})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SubscriptionCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # payload: price_id
        price_id = request.data.get('price_id')
        if not price_id:
            return Response({'error': 'price_id requerido'}, status=status.HTTP_400_BAD_REQUEST)
        if not hasattr(request.user, 'stripe_customer'):
            return Response({'error': 'stripe customer no encontrado'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            sub = fin_utils.create_subscription(request.user.stripe_customer.stripe_customer_id, price_id)
            return Response({'id': sub.id, 'status': sub.status})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PaymentListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # 'junta' role sees list but without usuario field; staff sees all; normal users see own
        role = getattr(request.user, 'rol', None)
        if request.user.is_staff:
            qs = Payment.objects.all().order_by('-created_at')
            data = PaymentSerializer(qs, many=True).data
            return Response(data)
        elif role == 'junta':
            qs = Payment.objects.all().order_by('-created_at')
            data = PaymentSerializer(qs, many=True).data
            # remove usuario field from each item
            for item in data:
                item.pop('usuario', None)
            return Response(data)
        else:
            qs = Payment.objects.filter(usuario=request.user).order_by('-created_at')
            data = PaymentSerializer(qs, many=True).data
            return Response(data)


class PaymentDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        payment = get_object_or_404(Payment, pk=pk)
        if not request.user.is_staff and payment.usuario != request.user:
            return Response({'error': 'sin permiso'}, status=status.HTTP_403_FORBIDDEN)
        return Response(PaymentSerializer(payment).data)


class ManualPaymentAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ManualPaymentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        amount = serializer.validated_data['amount']
        currency = serializer.validated_data.get('currency', 'usd')
        reference = serializer.validated_data.get('reference')
        # Limit manual payment amount for non-staff users
        MAX_MANUAL = 10_000_00  # e.g., $10,000 in cents
        try:
            if not request.user.is_staff and int(amount) > MAX_MANUAL:
                return Response({'error': 'amount exceeds manual limit'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({'error': 'invalid amount'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            now_ts = int(timezone.now().timestamp())
            pi_id = f"manual-{request.user.id}-{now_ts}"
            payment = Payment.objects.create(usuario=request.user, stripe_payment_intent=pi_id, amount=int(amount), currency=currency, status='succeeded')
            return Response({'id': payment.id, 'status': payment.status}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GatewaysListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # if admin route requested, ensure only staff can access
        if getattr(request.user, 'is_staff', False) is False and request.path.endswith('/admin/'):
            return Response({'error': 'sin permiso'}, status=status.HTTP_403_FORBIDDEN)
        qs = PaymentGateway.objects.filter(enabled=True)
        data = PaymentGatewaySerializer(qs, many=True).data
        return Response(data)


class InvoicesListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_staff:
            qs = Invoice.objects.all().order_by('-issued_at')
        else:
            qs = Invoice.objects.filter(usuario=request.user).order_by('-issued_at')
        data = InvoiceSerializer(qs, many=True).data
        return Response(data)

    def post(self, request):
        serializer = InvoiceCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        usuario_id = data.get('usuario_id')
        # owner: staff can create for others
        if request.user.is_staff and usuario_id:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            usuario = get_object_or_404(User, pk=usuario_id)
        else:
            usuario = request.user
        invoice = Invoice.objects.create(usuario=usuario, amount=int(data['amount']), currency=data.get('currency','usd'), description=data.get('description',''), due_date=data.get('due_date', None))
        try:
            invoice.generate_pdf_qr()
        except Exception:
            pass
        return Response(InvoiceSerializer(invoice).data, status=status.HTTP_201_CREATED)


class ProductPriceAdminAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # create product or price depending on payload
        if not request.user.is_staff:
            return Response({'error': 'sin permiso'}, status=status.HTTP_403_FORBIDDEN)
        if 'name' in request.data:
            serializer = ProductCreateSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            try:
                product = fin_utils.create_product(name=data['name'], description=data.get('description'))
                # persist locally
                from .models import Product as ProductModel
                prod = ProductModel.objects.create(stripe_product_id=product.id, name=product.name, description=getattr(product,'description',''))
                return Response(ProductModelSerializer(prod).data)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        elif 'product_id' in request.data:
            serializer = PriceCreateSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
            try:
                price = fin_utils.create_price(product_id=data['product_id'], unit_amount=data['unit_amount'], currency=data.get('currency','usd'), recurring=data.get('recurring'))
                # persist locally
                from .models import Price as PriceModel, Product as ProductModel
                prod = ProductModel.objects.filter(stripe_product_id=price.product).first()
                if not prod:
                    # create a minimal product record
                    prod = ProductModel.objects.create(stripe_product_id=price.product, name=str(price.product), description='')
                pr = PriceModel.objects.create(stripe_price_id=price.id, product=prod, unit_amount=price.unit_amount, currency=price.currency, recurring=getattr(price,'recurring', None) or None)
                return Response(PriceModelSerializer(pr).data)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'error': 'payload inválido'}, status=status.HTTP_400_BAD_REQUEST)


class ProductListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .models import Product
        qs = Product.objects.all().order_by('-created_at')
        return Response(ProductModelSerializer(qs, many=True).data)


class PriceListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .models import Price
        qs = Price.objects.all().order_by('-created_at')
        return Response(PriceModelSerializer(qs, many=True).data)


class RefundAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not request.user.is_staff:
            return Response({'error': 'sin permiso'}, status=status.HTTP_403_FORBIDDEN)
        payment_intent = request.data.get('payment_intent')
        amount = request.data.get('amount')
        if not payment_intent:
            return Response({'error': 'payment_intent requerido'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            refund = fin_utils.create_refund(payment_intent, amount=int(amount) if amount else None)
            # Optionally email receipt
            try:
                send_mail('Refund processed', f'Refund for {payment_intent}: {refund.id}', None, [request.user.email])
            except Exception:
                logging.exception('Failed to send refund email')
            return Response({'id': getattr(refund, 'id', None)})
        except Exception as e:
            logging.exception('Refund failed')
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class InvoiceDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        invoice = get_object_or_404(Invoice, pk=pk)
        if not request.user.is_staff and invoice.usuario != request.user:
            return Response({'error': 'sin permiso'}, status=status.HTTP_403_FORBIDDEN)
        return Response(InvoiceSerializer(invoice).data)


class InvoiceDownloadAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        invoice = get_object_or_404(Invoice, pk=pk)
        if not request.user.is_staff and invoice.usuario != request.user:
            return Response({'error': 'sin permiso'}, status=status.HTTP_403_FORBIDDEN)
        # ensure pdf exists
        media_path = None
        if invoice.pdf_url:
            # pdf_url stored as MEDIA_URL/path
            rel = invoice.pdf_url.replace(settings.MEDIA_URL, '').lstrip('/\\')
            media_path = os.path.join(settings.MEDIA_ROOT, rel)
        if not media_path or not os.path.exists(media_path):
            try:
                invoice.generate_pdf_qr()
                rel = invoice.pdf_url.replace(settings.MEDIA_URL, '').lstrip('/\\')
                media_path = os.path.join(settings.MEDIA_ROOT, rel)
            except Exception:
                raise Http404
        return FileResponse(open(media_path, 'rb'), content_type='application/pdf')


class OverdueChargeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # only staff may apply charges
        if not request.user.is_staff:
            return Response({'error': 'sin permiso'}, status=status.HTTP_403_FORBIDDEN)
        serializer = OverdueChargeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        from django.contrib.auth import get_user_model
        User = get_user_model()
        usuario = get_object_or_404(User, pk=data['usuario_id'])
        invoice = None
        if data.get('invoice_id'):
            invoice = get_object_or_404(Invoice, pk=data['invoice_id'])
        charge = OverdueCharge.objects.create(usuario=usuario, invoice=invoice, amount=int(data['amount']), reason=data.get('reason',''), applied_by=request.user)
        return Response({'id': charge.id}, status=status.HTTP_201_CREATED)


class PayrollListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_staff:
            return Response({'error': 'sin permiso'}, status=status.HTTP_403_FORBIDDEN)
        qs = Payroll.objects.all().order_by('-created_at')
        data = [{'id': p.id, 'name': p.name, 'period_start': p.period_start, 'period_end': p.period_end, 'total_amount': p.total_amount, 'status': p.status} for p in qs]
        return Response(data)

    def post(self, request):
        if not request.user.is_staff:
            return Response({'error': 'sin permiso'}, status=status.HTTP_403_FORBIDDEN)
        serializer = PayrollSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        payroll = Payroll.objects.create(name=data['name'], period_start=data['period_start'], period_end=data['period_end'], total_amount=int(data.get('total_amount',0)), created_by=request.user)
        return Response({'id': payroll.id}, status=status.HTTP_201_CREATED)
    
    # webhook handler implemetado en apps.finanzas.webhook