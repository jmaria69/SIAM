"""Praxia Active Defense (módulo premium, siem/active_defense.py +
siem/router/active_defense.py). Ver docstring de active_defense.py: reutiliza
el WAAP existente, solo añade agrupación por atacante/campaña + Response
Engine simulado detrás de settings.PRAXIA_ACTIVE_DEFENSE_ENABLED.
"""
from siem.active_defense import (
    compute_threat_score,
    list_attackers,
    list_campaigns,
    suggest_response,
)
from siem.config import Settings, get_settings
from siem.main import app
from siem.models import Event, Severity


def _waf_event(ip="1.2.3.4", severity=Severity.HIGH, category="sqli", **kwargs):
    return Event(
        source="waf-cloudflare",
        summary="WAF BLOCK",
        severity=severity,
        raw_payload={"client_ip": ip, "country": "ES", "asn": "AS1234", "attack_category": category},
        **kwargs,
    )


def test_suggest_response_maps_severity_to_action():
    assert suggest_response(Severity.CRITICAL) == "BLOCK"
    assert suggest_response(Severity.HIGH) == "RATE_LIMIT"
    assert suggest_response(Severity.MEDIUM) == "CHALLENGE"
    assert suggest_response(Severity.LOW) == "HONEYPOT"


def test_compute_threat_score_saturates_at_100():
    events = [_waf_event(severity=Severity.CRITICAL) for _ in range(10)]
    assert compute_threat_score(events) == 100
    assert compute_threat_score([]) == 0


def test_list_attackers_groups_by_client_ip():
    events = [
        _waf_event(ip="1.1.1.1", severity=Severity.HIGH),
        _waf_event(ip="1.1.1.1", severity=Severity.CRITICAL),
        _waf_event(ip="2.2.2.2", severity=Severity.LOW),
        Event(source="monitoring", summary="evento no-WAF sin client_ip"),
    ]
    attackers = list_attackers(events)

    assert len(attackers) == 2
    top = attackers[0]
    assert top["ip"] == "1.1.1.1"
    assert top["event_count"] == 2
    assert top["max_severity"] == "critica"
    assert top["suggested_action"] == "BLOCK"


def test_list_campaigns_requires_multiple_attackers_or_volume():
    # Un solo atacante con pocos eventos no es "campaña" -- ruido, no señal.
    quiet = list_attackers([_waf_event(ip="1.1.1.1")])
    assert list_campaigns(quiet) == []

    # Dos atacantes distintos con la misma categoría sí correlaciona.
    coordinated = list_attackers([
        _waf_event(ip="1.1.1.1", category="sqli"),
        _waf_event(ip="2.2.2.2", category="sqli"),
    ])
    campaigns = list_campaigns(coordinated)
    assert len(campaigns) == 1
    assert campaigns[0]["attack_category"] == "sqli"
    assert campaigns[0]["attacker_count"] == 2


def _enable_module():
    app.dependency_overrides[get_settings] = lambda: Settings(
        AI_PROVIDER="none", SMTP_HOST=None, ALERT_EMAIL_TO=None,
        PRAXIA_ACTIVE_DEFENSE_ENABLED=True,
    )


def _disable_module():
    app.dependency_overrides[get_settings] = lambda: Settings(
        AI_PROVIDER="none", SMTP_HOST=None, ALERT_EMAIL_TO=None,
    )


def test_overview_403_when_module_not_contratado(client):
    resp = client.get("/v1/active-defense/overview")
    assert resp.status_code == 403


def test_status_reports_enabled_flag(client):
    assert client.get("/v1/active-defense/status").json() == {"enabled": False}
    _enable_module()
    try:
        assert client.get("/v1/active-defense/status").json() == {"enabled": True}
    finally:
        _disable_module()


def test_overview_groups_ingested_waf_events_when_enabled(client):
    _enable_module()
    try:
        client.post("/v1/ingest/waf", json={"events": [
            {"source": "waf-cloudflare", "action": "block", "attack_category": "sqli",
             "client_ip": "9.9.9.9", "country": "ES", "host": "web-prod-01"},
        ]})
        resp = client.get("/v1/active-defense/overview")
        assert resp.status_code == 200
        body = resp.json()
        assert body["attackers"][0]["ip"] == "9.9.9.9"
        assert body["threat_score"] > 0
    finally:
        _disable_module()


def test_respond_requires_confirmation_then_executes(client):
    _enable_module()
    try:
        unconfirmed = client.post("/v1/active-defense/respond?ip=9.9.9.9&action=BLOCK")
        assert unconfirmed.json()["ejecutado"] is False

        confirmed = client.post("/v1/active-defense/respond?ip=9.9.9.9&action=BLOCK&confirm=true")
        assert confirmed.json()["ejecutado"] is True
    finally:
        _disable_module()
