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
import re
from email.mime.text import MIMEText

from siem.config import Settings
from siem.models import Incident, Severity

logger = logging.getLogger("siem.notifications")

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

_SEVERITY_LABEL = {
    Severity.INFO: "Info",
    Severity.LOW: "Baja",
    Severity.MEDIUM: "Media",
    Severity.HIGH: "Alta",
    Severity.CRITICAL: "Crítica",
}

_SEVERITY_COLOR = {
    Severity.INFO: ("#e0e7ff", "#3730a3"),
    Severity.LOW: ("#dcfce7", "#166534"),
    Severity.MEDIUM: ("#fef9c3", "#854d0e"),
    Severity.HIGH: ("#ffedd5", "#9a3412"),
    Severity.CRITICAL: ("#fee2e2", "#991b1b"),
}

_DASHBOARD_URL = "https://siem.praxialabs.com"


def _cuerpo_html(incident: Incident) -> str:
    """Genera el cuerpo HTML de la notificación de incidente SIEM con el mismo
    diseño que las alertas de EmailJS del web."""
    # Map severity to label and color
    severity_label = _SEVERITY_LABEL[incident.severity]
    bg_color, fg_color = _SEVERITY_COLOR[incident.severity]

    # Format date in Spanish (using updated_at for when incident was last modified)
    try:
        from datetime import datetime
        dt = incident.updated_at
        fecha_hora = dt.strftime("%d/%m/%Y, %H:%M:%S")
    except:
        fecha_hora = str(incident.updated_at)  # fallback

    # Determine tipo de ataque (simplified - could be enhanced)
    tipo_ataque = "Incidente de seguridad correlacionado"
    # TODO: Could improve by checking incident.title or recommendations for keywords

    # Determine IP atacante (simplified)
    # Look for IP addresses in affected_assets
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ips = [asset for asset in incident.affected_assets if ip_pattern.match(asset)]
    ip_atacante = ips[0] if ips else (
        f"{len(incident.affected_assets)} activos afectados"
        if incident.affected_assets else "No especificado"
    )

    # Resumen: short summary (use title)
    resumen = incident.title[:100] + ("..." if len(incident.title) > 100 else "")

    # Detalles técnicos: full description
    detalles = incident.description or "No se proporcionaron detalles adicionales."

    # Solucion: numbered steps from recommendations
    if incident.recommendations:
        solucion_steps = []
        for i, rec in enumerate(incident.recommendations, 1):
            solucion_steps.append(f"{i}. {rec}")
        solucion = "\n".join(solucion_steps)
    else:
        solucion = "1. Revisa el incidente en el panel del SOC para más contexto.\n2. Determina si se requiere acción basada en la severidad y los activos afectados."

    # Panel URL - using SIEM dashboard
    panel_url = _DASHBOARD_URL

    # Return the exact same HTML structure as the EmailJS template
    return f"""
<div style="font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; max-width: 560px; margin: 0 auto; background:#0f172a; color:#e2e8f0; border-radius: 12px; overflow: hidden; border: 1px solid #1e293b;">
  <!-- Header -->
  <div style="background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 24px 28px;">
    <p style="margin:0; font-size: 12px; letter-spacing: 1px; text-transform: uppercase; color: #e0e7ff; font-weight: 600;">Praxia Labs · Centro de Seguridad</p>
    <h1 style="margin: 6px 0 0; font-size: 20px; color: #ffffff;">🚨 Alerta de seguridad detectada</h1>
  </div>

  <!-- Severity badge -->
  <div style="padding: 20px 28px 0;">
    <span style="display:inline-block; padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 700; letter-spacing: 0.5px; background:{bg_color}; color:{fg_color};">
      SEVERIDAD: {severity_label}
    </span>
  </div>

  <!-- Summary -->
  <div style="padding: 16px 28px 0;">
    <table role="presentation" style="width:100%; border-collapse: collapse; font-size: 14px;">
      <tr>
        <td style="padding: 8px 0; color:#94a3b8; width: 120px;">ID incidente</td>
        <td style="padding: 8px 0; color:#f1f5f9; font-weight: 600; font-family: monospace;">{incident.id}</td>
      </tr>
      <tr style="border-top: 1px solid #1e293b;">
        <td style="padding: 8px 0; color:#94a3b8;">Tipo de ataque</td>
        <td style="padding: 8px 0; color:#f1f5f9; font-weight: 600;">{tipo_ataque}</td>
      </tr>
      <tr style="border-top: 1px solid #1e293b;">
        <td style="padding: 8px 0; color:#94a3b8;">IP atacante</td>
        <td style="padding: 8px 0; color:#f1f5f9; font-family: monospace;">{ip_atacante}</td>
      </tr>
      <tr style="border-top: 1px solid #1e293b;">
        <td style="padding: 8px 0; color:#94a3b8;">Fecha y hora</td>
        <td style="padding: 8px 0; color:#f1f5f9;>{fecha_hora}</td>
      </tr>
    </table>
  </div>

  <!-- Summary of the attack -->
  <div style="padding: 16px 28px 0;">
    <p style="margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color:#94a3b8; font-weight: 700;">Resumen</p>
    <p style="margin:0; font-size: 14px; line-height: 1.5; color:#f1f5f9; font-weight: 500;>{resumen}</p>
  </div>

  <!-- Details -->
  <div style="padding: 16px 28px 0;">
    <p style="margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color:#94a3b8; font-weight: 700;">Detalles técnicos</p>
    <p style="margin:0; font-size: 14px; line-height: 1.5; color:#cbd5e1; background:#1e293b; padding: 12px 14px; border-radius: 8px;>{detalles}</p>
  </div>

  <!-- Solution -->
  <div style="padding: 16px 28px 0;">
    <p style="margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color:#cbd5e1; background:#0b2f22; border: 1px solid #14532d; padding: 12px 14px; border-radius: 8px; white-space: pre-line;>{solucion}</p>
  </div>

  <!-- CTA -->
  <div style="padding: 24px 28px 28px; text-align: center;">
    <a href="{panel_url}" style="display:inline-block; background:#4f46e5; color:#ffffff; text-decoration:none; font-weight: 600; font-size: 14px; padding: 12px 24px; border-radius: 8px;">
      Ver en el Centro de Seguridad →
    </a>
  </div>

  <!-- Footer -->
  <div style="padding: 14px 28px; border-top: 1px solid #1e293b; text-align:center;">
    <p style="margin:0; font-size: 11px; color:#64748b;">Alerta automática de praxialabs.com — no respondas a este email.</p>
  </div>
</div>
"""


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
    return enviar_email(settings, settings.ALERT_EMAIL_TO, asunto, _cuerpo_html(incident))