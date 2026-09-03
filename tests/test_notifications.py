"""Tests de siem/notifications.py::notificar_incidente — la alerta por email
al crear un incidente NUEVO (siem/correlation.py::correlate_event). Antes de
esto, un incidente nunca disparaba ningún email; solo existía enviar_email
para campañas de concienciación.
"""
from siem.config import Settings
from siem.models import Incident, Severity
from siem.notifications import notificar_incidente


def _incident(severity: Severity = Severity.HIGH) -> Incident:
    return Incident(title="Login sospechoso", severity=severity, description="Detalle")


def test_sin_alert_email_to_no_intenta_enviar(monkeypatch):
    called = False

    def _fake_enviar_email(*a, **kw):
        nonlocal called
        called = True
        return True

    monkeypatch.setattr("siem.notifications.enviar_email", _fake_enviar_email)
    settings = Settings(SMTP_HOST="smtp.example.com", SMTP_USER="u", SMTP_PASSWORD="p", ALERT_EMAIL_TO=None)

    assert notificar_incidente(settings, _incident()) is False
    assert called is False


def test_severidad_por_debajo_del_umbral_no_envia(monkeypatch):
    called = False

    def _fake_enviar_email(*a, **kw):
        nonlocal called
        called = True
        return True

    monkeypatch.setattr("siem.notifications.enviar_email", _fake_enviar_email)
    settings = Settings(ALERT_EMAIL_TO="soc@empresa.com", ALERT_EMAIL_MIN_SEVERITY="alta")

    assert notificar_incidente(settings, _incident(Severity.LOW)) is False
    assert called is False


def test_severidad_igual_o_por_encima_del_umbral_envia(monkeypatch):
    captured = {}

    def _fake_enviar_email(settings, destinatario, asunto, cuerpo_html):
        captured["destinatario"] = destinatario
        captured["asunto"] = asunto
        captured["cuerpo_html"] = cuerpo_html
        return True

    monkeypatch.setattr("siem.notifications.enviar_email", _fake_enviar_email)
    settings = Settings(ALERT_EMAIL_TO="soc@empresa.com", ALERT_EMAIL_MIN_SEVERITY="media")
    incident = _incident(Severity.CRITICAL)

    assert notificar_incidente(settings, incident) is True
    assert captured["destinatario"] == "soc@empresa.com"
    assert incident.title in captured["asunto"]
    assert incident.id in captured["cuerpo_html"]
