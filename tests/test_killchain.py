"""Tests de la reconstrucción de kill-chain (siem/killchain.py + endpoint
POST /v1/incidents/{id}/kill-chain).

Cubre la pieza diferencial: eventos correlacionados en un incidente se ordenan
como pasos de un ataque en el marco MITRE ATT&CK, de "cómo entró" a "qué
impacto tuvo", independientemente del orden en que se ingirieron. Con
AI_PROVIDER=none (forzado en conftest), la narración cae en la plantilla
determinista -- así estos tests no dependen de ningún LLM externo.
"""
from siem.killchain import build_kill_chain
from siem.models import Event, Incident, Severity


def _ingest(client, summary, asset_name="web-prod-01", severity="alta"):
    return client.post(
        "/v1/monitoring/ingest",
        json={
            "source": "test",
            "asset_name": asset_name,
            "event_type": "generico",
            "severity": severity,
            "summary": summary,
        },
    )


def test_build_kill_chain_orders_by_attack_tactic_not_insertion_order():
    """El paso de Impacto (ransomware) es el MÁS TEMPRANO en el tiempo, pero
    debe quedar el ÚLTIMO de la cadena; el Acceso inicial (phishing) el
    primero. Comprueba que se ordena por ATT&CK, no por timestamp de ingesta."""
    from datetime import datetime, timedelta

    base = datetime(2026, 7, 27, 10, 0, 0)
    incident = Incident(id="INC-test", title="Cadena de prueba")
    # ransomware primero en el tiempo (Impact, rank alto -> debería ir al final)
    e_ransom = Event(source="t", summary="ransomware: archivos cifrados", threat_ids=[6], timestamp=base)
    e_phish = Event(source="t", summary="correo de phishing", threat_ids=[3], timestamp=base + timedelta(minutes=1))
    e_brute = Event(source="t", summary="fuerza bruta, multiples intentos de login", threat_ids=[12], timestamp=base + timedelta(minutes=2))

    steps = build_kill_chain(incident, [e_ransom, e_phish, e_brute])

    tactics = [s.tactic_id for s in steps]
    assert tactics == ["TA0001", "TA0006", "TA0040"]  # Acceso inicial -> Credenciales -> Impacto
    assert [s.order for s in steps] == [1, 2, 3]
    assert steps[0].technique_id == "T1566"   # Phishing
    assert steps[-1].threat_name == "Ransomware"


def test_build_kill_chain_dedupes_repeated_technique_keeping_earliest_event():
    """Tres eventos que disparan la MISMA amenaza producen UN solo paso,
    anclado al evento más temprano."""
    from datetime import datetime, timedelta

    base = datetime(2026, 7, 27, 10, 0, 0)
    incident = Incident(id="INC-test", title="Repetida")
    events = [
        Event(source="t", summary="correo de phishing #1", asset_name="pc-01", threat_ids=[3], timestamp=base + timedelta(minutes=2)),
        Event(source="t", summary="correo de phishing #0", asset_name="pc-01", threat_ids=[3], timestamp=base),
        Event(source="t", summary="correo de phishing #1b", asset_name="pc-01", threat_ids=[3], timestamp=base + timedelta(minutes=5)),
    ]
    steps = build_kill_chain(incident, events)
    assert len(steps) == 1
    assert steps[0].event_summary == "correo de phishing #0"  # el más temprano


def test_kill_chain_endpoint_returns_steps_and_narrative(client):
    # Mismo activo -> mismo incidente por correlación. Orden de ingesta mezclado
    # a propósito para probar el reordenado ATT&CK del endpoint completo.
    _ingest(client, "ransomware: archivos cifrados", severity="critica")
    _ingest(client, "correo de phishing con enlace de phishing")
    _ingest(client, "fuerza bruta, multiples intentos de login")

    incident_id = client.get("/v1/incidents").json()[0]["id"]
    resp = client.post(f"/v1/incidents/{incident_id}/kill-chain")
    assert resp.status_code == 200
    body = resp.json()

    assert "reglas" in body["proveedor_ia"]  # AI_PROVIDER=none en tests
    assert body["narrativa"]
    tactics = [s["tactic_id"] for s in body["kill_chain"]]
    assert tactics == ["TA0001", "TA0006", "TA0040"]
    # cada paso lleva su técnica ATT&CK y su evidencia
    assert all(s["technique_id"] and s["event_summary"] for s in body["kill_chain"])


def test_kill_chain_endpoint_records_timeline_entry(client):
    _ingest(client, "correo de phishing")
    incident_id = client.get("/v1/incidents").json()[0]["id"]
    client.post(f"/v1/incidents/{incident_id}/kill-chain")

    incident = client.get(f"/v1/incidents/{incident_id}").json()
    ia_entries = [t for t in incident["timeline"] if t["actor"] == "IA" and "Kill-chain" in t["description"]]
    assert len(ia_entries) == 1


def test_kill_chain_endpoint_404_on_missing_incident(client):
    assert client.post("/v1/incidents/INC-nope/kill-chain").status_code == 404


def test_kill_chain_narrative_plain_when_no_threats(client):
    # Evento sin ninguna keyword del catálogo -> incidente sin pasos mapeados.
    _ingest(client, "evento neutro sin indicadores")
    incident_id = client.get("/v1/incidents").json()[0]["id"]
    body = client.post(f"/v1/incidents/{incident_id}/kill-chain").json()
    assert body["kill_chain"] == []
    assert "No se pudo reconstruir" in body["narrativa"]
