from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from io import BytesIO
import qrcode
import json
import hmac
import hashlib
import base64
from django.conf import settings
import os


def _format_money(cents, currency='usd'):
    try:
        amount = cents / 100
        return f"{amount:,.2f} {currency.upper()}"
    except Exception:
        return f"{cents}"


def _build_qr_payload(invoice):
    payload = {
        "v": "inv_v1",
        "id": f"inv_{invoice.id}",
        "amt": invoice.amount,
        "cur": getattr(invoice, 'currency', 'usd'),
        "iss": getattr(settings, 'DEFAULT_FROM_EMAIL', 'edificio'),
        "iat": invoice.issued_at.isoformat() if invoice.issued_at else None,
    }
    # sign with HMAC-SHA256 if key present
    key = getattr(settings, 'INVOICE_SIGNING_KEY', None)
    if key:
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode('utf-8')
        sig = hmac.new(key.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()
        payload['sig'] = sig
    # compact base64
    b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).decode()
    # If SITE_URL available, return full URL to the verify endpoint for easier mobile scanning
    site = getattr(settings, 'SITE_URL', None) or 'http://localhost:8000'
    verify_url = f"{site.rstrip('/')}/api/finanzas/invoices/verify/?t={b64}"
    return verify_url


def build_invoice_pdf_bytes(invoice, logo_path=None):
    """Genera el PDF de la factura y devuelve los bytes."""
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    story = []

    # Header: logo + issuer
    if logo_path is None:
        # buscar logo en static/images/logo.png
        candidate = os.path.join(settings.BASE_DIR, 'static', 'images', 'logo.png')
        if os.path.exists(candidate):
            logo_path = candidate
    if logo_path and os.path.exists(logo_path):
        try:
            img = Image(logo_path, width=40 * mm, height=20 * mm)
            story.append(img)
        except Exception:
            # ignore logo errors
            pass

    story.append(Paragraph(f"<b>Factura #{invoice.id}</b>", styles['Title']))
    story.append(Spacer(1, 6))

    meta = []
    meta.append(["Emitida:", invoice.issued_at.strftime('%Y-%m-%d %H:%M') if invoice.issued_at else ''])
    meta.append(["Vence:", invoice.due_date.isoformat() if invoice.due_date else ''])
    meta.append(["Usuario:", str(invoice.usuario)])
    meta_table = Table(meta, colWidths=[40 * mm, None])
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # Description and amount
    story.append(Paragraph(f"<b>Concepto:</b> {invoice.description}", styles['Normal']))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Importe:</b> {_format_money(invoice.amount, getattr(invoice, 'currency', 'usd'))}", styles['Heading2']))
    story.append(Spacer(1, 12))

    # QR generation
    qr_text = _build_qr_payload(invoice)
    qr_img = qrcode.make(qr_text)
    qr_buf = BytesIO()
    qr_img.save(qr_buf, format='PNG')
    qr_buf.seek(0)
    try:
        qr_buf.seek(0)
        qr_img_flowable = Image(qr_buf, width=40 * mm, height=40 * mm)
        # position QR bottom-right using a small table with an empty left cell
        qr_table = Table([["", qr_img_flowable]], colWidths=[None, 40 * mm])
        story.append(qr_table)
    except Exception:
        # fallback: embed as image via Image
        try:
            qr_buf.seek(0)
            img = Image(qr_buf, width=40 * mm, height=40 * mm)
            story.append(img)
        except Exception:
            pass

    # Footer note
    story.append(Spacer(1, 12))
    story.append(Paragraph("Escanee el QR para verificar la factura y/o iniciar el pago.", ParagraphStyle('foot', fontSize=8, textColor=colors.grey)))

    doc.build(story)
    pdf = buf.getvalue()
    buf.close()
    return pdf
