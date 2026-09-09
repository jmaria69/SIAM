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
    # CLOUDFLARE_API_TOKEN/ZONE_ID explícitos a None: sin esto, Settings()
    # cae al .env real y /respond haría llamadas de escritura DE VERDAD
    # contra Cloudflare (ver conftest.py y el repro de 2026-09-04).
    app.dependency_overrides[get_settings] = lambda: Settings(
        AI_PROVIDER="none", SMTP_HOST=None, ALERT_EMAIL_TO=None,
        PRAXIA_ACTIVE_DEFENSE_ENABLED=True,
        CLOUDFLARE_API_TOKEN=None, CLOUDFLARE_ZONE_ID=None,
    )


def _disable_module():
    app.dependency_overrides[get_settings] = lambda: Settings(
        AI_PROVIDER="none", SMTP_HOST=None, ALERT_EMAIL_TO=None,
        CLOUDFLARE_API_TOKEN=None, CLOUDFLARE_ZONE_ID=None,
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


def test_confirmed_block_marks_attacker_as_bloqueada_in_overview(client):
    _enable_module()
    try:
        client.post("/v1/ingest/waf", json={"events": [
            {"source": "waf-cloudflare", "action": "block", "attack_category": "sqli",
             "client_ip": "8.8.4.4", "country": "US"},
        ]})
        client.post("/v1/active-defense/respond?ip=8.8.4.4&action=BLOCK&confirm=true")

        overview = client.get("/v1/active-defense/overview").json()
        attacker = next(a for a in overview["attackers"] if a["ip"] == "8.8.4.4")
        assert attacker["status"] == "bloqueada"
    finally:
        _disable_module()


def test_whitelist_crud_and_respond_refuses_whitelisted_ip(client):
    _enable_module()
    try:
        created = client.post("/v1/active-defense/whitelist", json={"ip": "5.5.5.5", "reason": "escáner contratado"})
        assert created.status_code == 200
        entry_id = created.json()["id"]

        listed = client.get("/v1/active-defense/whitelist").json()
        assert any(w["ip"] == "5.5.5.5" for w in listed)

        blocked = client.post("/v1/active-defense/respond?ip=5.5.5.5&action=BLOCK&confirm=true")
        assert blocked.status_code == 409

        removed = client.delete(f"/v1/active-defense/whitelist/{entry_id}")
        assert removed.json()["eliminado"] is True
    finally:
        _disable_module()


def test_whitelisted_attacker_shows_lista_blanca_status(client):
    _enable_module()
    try:
        client.post("/v1/active-defense/whitelist", json={"ip": "3.3.3.3"})
        client.post("/v1/ingest/waf", json={"events": [
            {"source": "waf-cloudflare", "action": "log", "attack_category": "scanner",
             "client_ip": "3.3.3.3", "country": "ES"},
        ]})

        overview = client.get("/v1/active-defense/overview").json()
        attacker = next(a for a in overview["attackers"] if a["ip"] == "3.3.3.3")
        assert attacker["status"] == "lista_blanca"
    finally:
        _disable_module()


def _enable_module_with_cloudflare():
    # CLOUDFLARE_ACCOUNT_ID/KV_NAMESPACE_ID forzados a None: si no, Settings
    # (env_file=".env") los rellenaría con los valores reales del .env local
    # y el test de "se queda simulado sin KV" dejaría de probar lo que dice.
    app.dependency_overrides[get_settings] = lambda: Settings(
        AI_PROVIDER="none", SMTP_HOST=None, ALERT_EMAIL_TO=None,
        PRAXIA_ACTIVE_DEFENSE_ENABLED=True,
        CLOUDFLARE_API_TOKEN="fake-token", CLOUDFLARE_ZONE_ID="fake-zone",
        CLOUDFLARE_ACCOUNT_ID=None, CLOUDFLARE_RATE_LIMIT_KV_NAMESPACE_ID=None,
    )


def _enable_module_with_rate_limit():
    # Además del token/zone de siempre, RATE_LIMIT necesita account id +
    # KV namespace (ver siem/cloudflare_firewall.py::is_rate_limit_configured).
    app.dependency_overrides[get_settings] = lambda: Settings(
        AI_PROVIDER="none", SMTP_HOST=None, ALERT_EMAIL_TO=None,
        PRAXIA_ACTIVE_DEFENSE_ENABLED=True,
        CLOUDFLARE_API_TOKEN="fake-token", CLOUDFLARE_ZONE_ID="fake-zone",
        CLOUDFLARE_ACCOUNT_ID="fake-account", CLOUDFLARE_RATE_LIMIT_KV_NAMESPACE_ID="fake-kv-ns",
    )


def test_respond_block_uses_real_cloudflare_connector_when_configured(client, monkeypatch):
    """Regresión 2026-09-04: BLOCK/CHALLENGE tienen conector real (IP Access
    Rules) cuando hay CLOUDFLARE_API_TOKEN de escritura -- ver
    siem/cloudflare_firewall.py. Se mockea la llamada HTTP real."""
    import siem.router.active_defense as ad_router

    monkeypatch.setattr(ad_router, "create_access_rule", lambda settings, ip, mode, notes: "cf-rule-123")
    _enable_module_with_cloudflare()
    try:
        resp = client.post("/v1/active-defense/respond?ip=7.7.7.7&action=BLOCK&confirm=true")
        body = resp.json()
        assert body["ejecutado"] is True
        assert body["real"] is True
        assert "cf-rule-123" in body["resultado"]

        blacklist = client.get("/v1/active-defense/blacklist").json()
        entry = next(b for b in blacklist if b["value"] == "7.7.7.7")
        assert entry["cf_rule_id"] == "cf-rule-123"
    finally:
        _disable_module()


def test_respond_rate_limit_stays_simulated_without_kv_config(client, monkeypatch):
    """RATE_LIMIT se queda simulado si solo hay token/zone (BLOCK/CHALLENGE/
    HONEYPOT ya funcionando de verdad) pero falta el account id o el KV
    namespace propios de RATE_LIMIT -- ver
    siem/cloudflare_firewall.py::is_rate_limit_configured. Un cliente que
    aún no ha desplegado el Worker de rate limiting no debe ver este
    endpoint fallar."""
    import siem.router.active_defense as ad_router

    monkeypatch.setattr(ad_router, "sync_rate_limit_rule", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no debería llamarse")))
    _enable_module_with_cloudflare()  # sin CLOUDFLARE_ACCOUNT_ID / KV_NAMESPACE_ID
    try:
        resp = client.post("/v1/active-defense/respond?ip=7.7.7.8&action=RATE_LIMIT&confirm=true")
        body = resp.json()
        assert body["ejecutado"] is True
        assert body["real"] is False
        assert "simulada" in body["resultado"]

        blacklist = client.get("/v1/active-defense/blacklist").json()
        entry = next(b for b in blacklist if b["value"] == "7.7.7.8")
        assert entry["action"] == "RATE_LIMIT"
        assert entry["cf_rule_id"] is None
    finally:
        _disable_module()


def test_respond_rate_limit_uses_real_workers_kv_when_fully_configured(client, monkeypatch):
    """Con account id + KV namespace configurados (ver
    _enable_module_with_rate_limit), RATE_LIMIT sincroniza de verdad el
    Workers KV que lee workers/rate-limiter/ -- mismo patrón que HONEYPOT."""
    import siem.router.active_defense as ad_router

    calls = []
    monkeypatch.setattr(ad_router, "sync_rate_limit_rule", lambda settings, ips: calls.append(set(ips)))
    _enable_module_with_rate_limit()
    try:
        resp = client.post("/v1/active-defense/respond?ip=7.7.7.12&action=RATE_LIMIT&confirm=true")
        body = resp.json()
        assert body["ejecutado"] is True
        assert body["real"] is True
        assert len(calls) == 1
        assert calls[0] == {"7.7.7.12"}

        blacklist = client.get("/v1/active-defense/blacklist").json()
        entry = next(b for b in blacklist if b["value"] == "7.7.7.12")
        assert entry["action"] == "RATE_LIMIT"
        assert entry["cf_rule_id"] is None  # RATE_LIMIT nunca crea una regla propia
    finally:
        _disable_module()


def test_unblocking_a_rate_limited_ip_resyncs_kv_without_it(client, monkeypatch):
    import siem.router.active_defense as ad_router

    calls = []
    monkeypatch.setattr(ad_router, "sync_rate_limit_rule", lambda settings, ips: calls.append(set(ips)))
    _enable_module_with_rate_limit()
    try:
        client.post("/v1/active-defense/respond?ip=7.7.7.13&action=RATE_LIMIT&confirm=true")
        blacklist = client.get("/v1/active-defense/blacklist").json()
        ioc_id = next(b["id"] for b in blacklist if b["value"] == "7.7.7.13")

        removed = client.delete(f"/v1/active-defense/blacklist/{ioc_id}")
        assert removed.json()["eliminado"] is True
        assert calls[-1] == set()  # última sincronización ya no incluye la IP
    finally:
        _disable_module()


def test_respond_honeypot_uses_real_shared_redirect_rule_when_configured(client, monkeypatch):
    """HONEYPOT redirige a /admin (siem/router/honeypot.py) vía la regla
    compartida de la fase http_request_dynamic_redirect."""
    import siem.router.active_defense as ad_router

    calls = []
    monkeypatch.setattr(ad_router, "sync_honeypot_rule", lambda settings, ips, target_url: calls.append((set(ips), target_url)))
    _enable_module_with_cloudflare()
    try:
        resp = client.post("/v1/active-defense/respond?ip=7.7.7.9&action=HONEYPOT&confirm=true")
        body = resp.json()
        assert body["ejecutado"] is True
        assert body["real"] is True
        assert len(calls) == 1
        ips, target_url = calls[0]
        assert ips == {"7.7.7.9"}
        assert target_url.endswith("/admin")
    finally:
        _disable_module()


def test_unblocking_a_shared_rule_ip_resyncs_without_it(client, monkeypatch):
    import siem.router.active_defense as ad_router

    calls = []
    monkeypatch.setattr(ad_router, "sync_honeypot_rule", lambda settings, ips, target_url: calls.append(set(ips)))
    _enable_module_with_cloudflare()
    try:
        client.post("/v1/active-defense/respond?ip=7.7.7.11&action=HONEYPOT&confirm=true")
        blacklist = client.get("/v1/active-defense/blacklist").json()
        ioc_id = next(b["id"] for b in blacklist if b["value"] == "7.7.7.11")

        removed = client.delete(f"/v1/active-defense/blacklist/{ioc_id}")
        assert removed.json()["eliminado"] is True
        assert calls[-1] == set()  # última sincronización ya no incluye la IP
    finally:
        _disable_module()


def test_respond_block_failure_in_cloudflare_returns_502(client, monkeypatch):
    import siem.router.active_defense as ad_router
    from siem.cloudflare_firewall import CloudflareFirewallError

    def _boom(settings, ip, mode, notes):
        raise CloudflareFirewallError("boom")

    monkeypatch.setattr(ad_router, "create_access_rule", _boom)
    _enable_module_with_cloudflare()
    try:
        resp = client.post("/v1/active-defense/respond?ip=7.7.7.9&action=BLOCK&confirm=true")
        assert resp.status_code == 502
    finally:
        _disable_module()


def test_unblocking_a_real_block_deletes_the_cloudflare_rule(client, monkeypatch):
    import siem.router.active_defense as ad_router

    monkeypatch.setattr(ad_router, "create_access_rule", lambda settings, ip, mode, notes: "cf-rule-456")
    deleted_ids = []
    monkeypatch.setattr(ad_router, "delete_access_rule", lambda settings, rule_id: deleted_ids.append(rule_id))
    _enable_module_with_cloudflare()
    try:
        client.post("/v1/active-defense/respond?ip=7.7.7.10&action=BLOCK&confirm=true")
        blacklist = client.get("/v1/active-defense/blacklist").json()
        ioc_id = next(b["id"] for b in blacklist if b["value"] == "7.7.7.10")

        removed = client.delete(f"/v1/active-defense/blacklist/{ioc_id}")
        assert removed.json()["eliminado"] is True
        assert deleted_ids == ["cf-rule-456"]
    finally:
        _disable_module()


def test_blacklist_crud(client):
    _enable_module()
    try:
        created = client.post("/v1/active-defense/blacklist", json={"ip": "6.6.6.6", "reason": "brute force"})
        assert created.status_code == 200
        ioc_id = created.json()["id"]

        listed = client.get("/v1/active-defense/blacklist").json()
        assert any(b["value"] == "6.6.6.6" for b in listed)

        removed = client.delete(f"/v1/active-defense/blacklist/{ioc_id}")
        assert removed.json()["eliminado"] is True
    finally:
        _disable_module()
