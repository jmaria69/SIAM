"""Envío de notificaciones salientes por email (campañas de concienciación).

Mismo criterio que `enviar_telegram` en `simulate_crisis.py`: una
integración externa opcional (aquí, un servidor SMTP) nunca debe tumbar un
endpoint por falta de configuración. Si `SMTP_HOST`/`SMTP_USER`/
`SMTP_PASSWORD` no están en `.env`, se registra en el log y se devuelve
`False` en vez de lanzar una excepción -- el router decide qué hacer con
ese resultado (en `siem/router/campaigns.py`, cuenta el destinatario como
"omitido" en vez de fallar toda la campaña por un envío).
"""
import logging
import smtplib
from email.mime.text import MIMEText

from siem.config import Settings

logger = logging.getLogger("siem.notifications")


def enviar_email(settings: Settings, destinatario: str, asunto: str, cuerpo_html: str) -> bool:
    if not settings.SMTP_HOST or not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        logger.info(
            "SMTP no configurado (SMTP_HOST/SMTP_USER/SMTP_PASSWORD en .env) — "
            "se omite el envío a %s.",
            destinatario,
        )
        return False

    msg = MIMEText(cuerpo_html, "html", "utf-8")
    msg["Subject"] = asunto
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
    msg["To"] = destinatario

    try:
        # Puerto 465 es SSL implícito por convención (Hostinger lo usa como
        # puerto por defecto, igual que Gmail): la conexión ya va cifrada
        # desde el primer byte, no hay handshake STARTTLS. Cualquier otro
        # puerto (587, 25) es texto plano que se cifra después con
        # STARTTLS. Antes esto solo soportaba STARTTLS -- con un servidor
        # configurado en 465 se habría colgado o fallado con un error de
        # protocolo poco claro, en vez de un mensaje explicable.
        if settings.SMTP_PORT == 465:
            with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(msg["From"], [destinatario], msg.as_string())
        else:
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                if settings.SMTP_USE_TLS:
                    server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(msg["From"], [destinatario], msg.as_string())
        return True
    except Exception:
        logger.exception("Fallo enviando email a %s", destinatario)
        return False
