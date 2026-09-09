"""Agregador incremental de perfiles de atacante (siem/attacker_aggregator.py
+ SiemStore.aggregate_attacker_profiles/list_attacker_profiles).

Se testea la lógica de agregación de forma síncrona y directa contra una
base en memoria propia de este archivo (mismo patrón que
tests/test_campaign_scheduler.py) -- el bucle real (`run_scheduler_loop`,
que espera con `asyncio.sleep`) se deja fuera a propósito.

También se cubre, vía `client` (tests/conftest.py), que /v1/active-defense/
overview usa este pipeline en vez de reagrupar eventos crudos: un evento
recién ingerido debe verse reflejado sin esperar al tick del bucle de
fondo (aggregate_once corre síncrono dentro de overview()).
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from siem.active_defense import (
    PATTERN_MULTI_CATEGORY_CATEGORIES,
    PATTERN_PERSISTENT_ACTIVE_DAYS,
    PATTERN_REPEAT_OFFENDER_EVENTS,
    attacker_from_profile,
    pattern_flags,
)
from siem.attacker_aggregator import aggregate_once, apply_auto_responses
from siem.config import Settings, get_settings
from siem.main import app
from siem.models import Event, Severity
from siem.store import SiemStore

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_Session = sessionmaker(bind=_engine)


def setup_function(_):
    from siem.database import Base

    Base.metadata.create_all(bind=_engine)


def teardown_function(_):
    from siem.database import Base

    Base.metadata.drop_all(bind=_engine)


def _waf_event(ip="1.2.3.4", severity=Severity.HIGH, category="sqli", **kwargs):
    return Event(
        source="waf-cloudflare",
        summary="WAF BLOCK",
        severity=severity,
        raw_payload={"client_ip": ip, "country": "ES", "asn": "AS1234", "attack_category": category},
        **kwargs,
    )


def test_aggregate_once_with_no_events_returns_zero():
    db = _Session()
    try:
        store = SiemStore(db)
        assert aggregate_once(store) == 0
    finally:
        db.close()


def test_aggregate_once_groups_events_into_profile():
    db = _Session()
    try:
        store = SiemStore(db)
        store.add_event(_waf_event(ip="1.1.1.1", severity=Severity.HIGH))
        store.add_event(_waf_event(ip="1.1.1.1", severity=Severity.CRITICAL))
        store.add_event(_waf_event(ip="2.2.2.2", severity=Severity.LOW))

        processed = aggregate_once(store)
        assert processed == 3

        profiles = store.list_attacker_profiles()
        assert [p["ip"] for p in profiles] == ["1.1.1.1", "2.2.2.2"]  # orden por threat_score desc
        top = profiles[0]
        assert top["event_count"] == 2
        assert top["max_severity"] == "critica"
        assert top["threat_score"] > 0
    finally:
        db.close()


def test_aggregate_once_is_incremental_and_does_not_reprocess():
    db = _Session()
    try:
        store = SiemStore(db)
        store.add_event(_waf_event(ip="3.3.3.3"))
        assert aggregate_once(store) == 1
        # Sin eventos nuevos desde el cursor, el segundo tick no tiene nada
        # que procesar.
        assert aggregate_once(store) == 0

        store.add_event(_waf_event(ip="3.3.3.3"))
        assert aggregate_once(store) == 1
        assert store.list_attacker_profiles()[0]["event_count"] == 2
    finally:
        db.close()


def test_aggregate_once_ignores_non_waf_events():
    db = _Session()
    try:
        store = SiemStore(db)
        # La query de aggregate_attacker_profiles filtra por WAF_SOURCES en
        # SQL (store.py:336) -- un evento de otra fuente ni siquiera se lee,
        # no cuenta como "procesado".
        store.add_event(Event(source="monitoring", summary="evento no-WAF sin client_ip"))
        assert aggregate_once(store) == 0
        assert store.list_attacker_profiles() == []
    finally:
        db.close()


def test_pattern_flags_thresholds():
    quiet = {"event_count": 1, "attack_categories": ["sqli"], "active_days": ["2026-01-01"]}
    assert pattern_flags(quiet) == []

    repeat_offender = {
        "event_count": PATTERN_REPEAT_OFFENDER_EVENTS,
        "attack_categories": ["sqli"],
        "active_days": ["2026-01-01"],
    }
    assert pattern_flags(repeat_offender) == ["reincidente"]

    noisy = {
        "event_count": PATTERN_REPEAT_OFFENDER_EVENTS,
        "attack_categories": [f"cat{i}" for i in range(PATTERN_MULTI_CATEGORY_CATEGORIES)],
        "active_days": [f"2026-01-{d:02d}" for d in range(1, PATTERN_PERSISTENT_ACTIVE_DAYS + 1)],
    }
    assert set(pattern_flags(noisy)) == {"reincidente", "multi_categoria", "persistente"}


def test_attacker_from_profile_maps_status():
    profile = {
        "ip": "9.9.9.9", "country": "ES", "asn": None, "asn_org": None,
        "event_count": 1, "attack_categories": [], "max_severity": "alta",
        "threat_score": 18, "active_days": ["2026-01-01"],
        "first_seen": None, "last_seen": None,
        "last_host": None, "last_uri": None, "last_user_agent": None, "referer_host": None,
    }
    assert attacker_from_profile(profile)["status"] == "activa"
    assert attacker_from_profile(profile, blocked_ips={"9.9.9.9"})["status"] == "bloqueada"
    assert attacker_from_profile(profile, whitelisted_ips={"9.9.9.9"})["status"] == "lista_blanca"


def _enable_module():
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


def test_overview_reflects_freshly_ingested_event_without_waiting_for_background_tick(client):
    _enable_module()
    try:
        client.post("/v1/ingest/waf", json={"events": [
            {"source": "waf-cloudflare", "action": "block", "attack_category": "sqli",
             "client_ip": "5.5.5.5", "country": "ES"},
        ]})
        body = client.get("/v1/active-defense/overview").json()
        attacker = next(a for a in body["attackers"] if a["ip"] == "5.5.5.5")
        assert attacker["event_count"] == 1
        assert "pattern_flags" in attacker
    finally:
        _disable_module()


def test_overview_marks_repeat_offender_pattern_flag(client):
    _enable_module()
    try:
        events = [
            {"source": "waf-cloudflare", "action": "block", "attack_category": "sqli",
             "client_ip": "6.6.6.6", "country": "ES"}
            for _ in range(PATTERN_REPEAT_OFFENDER_EVENTS)
        ]
        client.post("/v1/ingest/waf", json={"events": events})
        body = client.get("/v1/active-defense/overview").json()
        attacker = next(a for a in body["attackers"] if a["ip"] == "6.6.6.6")
        assert "reincidente" in attacker["pattern_flags"]
    finally:
        _disable_module()


# ---------------------------------------------------------------------------
# apply_auto_responses -- auto-honeypot de reincidentes + enriquecimiento
# WHOIS/RDAP (siem/attacker_aggregator.py + siem/response_actions.py +
# siem/ip_intel.py). Sin credenciales de Cloudflare configuradas, HONEYPOT
# se queda simulado pero igualmente registra el IOC -- suficiente para
# comprobar la lógica de decisión sin mockear la red.
# ---------------------------------------------------------------------------

def _settings(**overrides) -> Settings:
    base = dict(
        AI_PROVIDER="none", SMTP_HOST=None, ALERT_EMAIL_TO=None,
        CLOUDFLARE_API_TOKEN=None, CLOUDFLARE_ZONE_ID=None,
        PRAXIA_ACTIVE_DEFENSE_ENABLED=True,
        PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS=False,
        PRAXIA_IP_INTEL_ENABLED=False,
    )
    base.update(overrides)
    return Settings(**base)


def _seed_repeat_offender(store: SiemStore, ip: str = "8.8.8.8") -> None:
    for _ in range(PATTERN_REPEAT_OFFENDER_EVENTS):
        store.add_event(_waf_event(ip=ip))
    aggregate_once(store)


def test_apply_auto_responses_does_nothing_when_flags_disabled():
    db = _Session()
    try:
        store = SiemStore(db)
        _seed_repeat_offender(store)
        acted = apply_auto_responses(store, _settings())
        assert acted == []
        assert store.list_iocs() == []
    finally:
        db.close()


def test_apply_auto_responses_honeypots_repeat_offenders_when_enabled():
    db = _Session()
    try:
        store = SiemStore(db)
        _seed_repeat_offender(store, ip="8.8.8.8")
        acted = apply_auto_responses(store, _settings(PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS=True))
        assert acted == ["8.8.8.8"]

        iocs = store.list_iocs()
        assert len(iocs) == 1
        assert iocs[0].value == "8.8.8.8"
        assert iocs[0].action == "HONEYPOT"
        assert iocs[0].confidence == "media"
        assert "reincidente" in iocs[0].campaign

        # Reconfirmar en el siguiente tick no debe duplicar el IOC.
        acted_again = apply_auto_responses(store, _settings(PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS=True))
        assert acted_again == []
        assert len(store.list_iocs()) == 1
    finally:
        db.close()


def test_apply_auto_responses_skips_whitelisted_ips():
    from siem.models import WhitelistEntry

    db = _Session()
    try:
        store = SiemStore(db)
        _seed_repeat_offender(store, ip="8.8.8.8")
        store.add_whitelist_entry(WhitelistEntry(ip="8.8.8.8", reason="proveedor"))

        acted = apply_auto_responses(store, _settings(PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS=True))
        assert acted == []
        assert store.list_iocs() == []
    finally:
        db.close()


def test_apply_auto_responses_skips_already_blocked_ips():
    from siem.models import IOC

    db = _Session()
    try:
        store = SiemStore(db)
        _seed_repeat_offender(store, ip="8.8.8.8")
        store.add_ioc(IOC(type="ip", value="8.8.8.8", confidence="alta", action="BLOCK"))

        acted = apply_auto_responses(store, _settings(PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS=True))
        assert acted == []
        # el BLOCK manual sigue intacto, no se sustituye por el auto-honeypot
        iocs = store.list_iocs()
        assert len(iocs) == 1
        assert iocs[0].action == "BLOCK"
    finally:
        db.close()


def test_apply_auto_responses_enriches_repeat_offenders_with_ip_intel(monkeypatch):
    db = _Session()
    try:
        store = SiemStore(db)
        _seed_repeat_offender(store, ip="8.8.8.8")

        monkeypatch.setattr(
            "siem.ip_intel.lookup_ip",
            lambda ip: {"org": "Google LLC", "network_name": "GOOGLE", "abuse_email": "abuse@google.com"},
        )
        apply_auto_responses(store, _settings(PRAXIA_IP_INTEL_ENABLED=True))

        profile = store.list_attacker_profiles()[0]
        assert profile["whois_org"] == "Google LLC"
        assert profile["whois_network_name"] == "GOOGLE"
        assert profile["whois_abuse_email"] == "abuse@google.com"
        assert profile["intel_fetched_at"] is not None
    finally:
        db.close()


def test_apply_auto_responses_does_not_retry_ip_intel_once_fetched(monkeypatch):
    db = _Session()
    try:
        store = SiemStore(db)
        _seed_repeat_offender(store, ip="8.8.8.8")

        calls = []
        monkeypatch.setattr(
            "siem.ip_intel.lookup_ip",
            lambda ip: calls.append(ip) or None,
        )
        apply_auto_responses(store, _settings(PRAXIA_IP_INTEL_ENABLED=True))
        apply_auto_responses(store, _settings(PRAXIA_IP_INTEL_ENABLED=True))
        assert calls == ["8.8.8.8"]  # solo se intenta una vez, incluso sin datos útiles
    finally:
        db.close()
