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
from siem.models import Incident, Severity

logger = logging.getLogger("siem.notifications")

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


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


def notificar_incidente(settings: Settings, incident: Incident) -> bool:
    """Alerta por email al SOC. `siem/correlation.py::correlate_event` la
    llama en dos momentos: al crear un incidente NUEVO, y de nuevo si un
    evento correlacionado contra uno ya abierto hace ESCALAR su severidad
    (p.ej. media -> crítica). No se repite por cada evento que se limita a
    sumarse sin cambiar la severidad -- eso sería ruido, no información
    nueva para el SOC.

    Se omite en silencio si ALERT_EMAIL_TO no está en .env o si la
    severidad no alcanza ALERT_EMAIL_MIN_SEVERITY -- misma filosofía que
    `enviar_email`: nunca debe tumbar la ingesta/correlación de eventos.
    """
    if not settings.ALERT_EMAIL_TO:
        return False
    umbral = Severity(settings.ALERT_EMAIL_MIN_SEVERITY)
    if _SEVERITY_ORDER.index(incident.severity) < _SEVERITY_ORDER.index(umbral):
        return False

    asunto = f"[SIAM] Incidente {incident.severity.value.upper()} — {incident.title}"
    cuerpo = (
        f"<h2>{incident.title}</h2>"
        f"<p><b>ID:</b> {incident.id}<br>"
        f"<b>Severidad:</b> {incident.severity.value}<br>"
        f"<b>Riesgo:</b> {incident.risk_score}/100<br>"
        f"<b>Activos afectados:</b> {', '.join(incident.affected_assets) or '—'}</p>"
        f"<p>{incident.description}</p>"
    )
    return enviar_email(settings, settings.ALERT_EMAIL_TO, asunto, cuerpo)
