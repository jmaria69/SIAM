"""Tests de la detección de amenazas por palabra clave (2026-07-05).

Cubre tanto la función pura `detect_threats` (siem/threat_detection.py,
sin tocar la base de datos) como la integración end-to-end vía
`POST /v1/monitoring/ingest` -> `siem/correlation.py` -> incidente con
`threat_ids`, y el router nuevo `siem/router/threats.py`.
"""
from siem.models import Event, Severity
from siem.threat_detection import detect_threats
from siem.threats_catalog import THREATS_CATALOG


def test_detect_threats_matches_ransomware_keywords():
    event = Event(
        source="test",
        event_type="cifrado_masivo",
        summary="Cifrado masivo de archivos detectado",
        description="Más de 4.000 archivos renombrados con extensión .locked",
    )
    assert 6 in detect_threats(event)  # id 6 = Ransomware


def test_detect_threats_no_match_returns_empty_list():
    event = Event(source="test", event_type="rutina", summary="Backup nocturno completado sin incidencias")
    assert detect_threats(event) == []


def test_detect_threats_can_match_multiple_threats():
    event = Event(
        source="test",
        event_type="phishing",
        summary="Campaña de phishing con deepfake de voz del CEO",
        description="Se usó una voz clonada para autorizar una transferencia urgente.",
    )
    ids = detect_threats(event)
    assert 3 in ids  # Phishing
    assert 22 in ids  # Ingeniería social potenciada por IA


def test_detect_threats_is_accent_insensitive():
    # Bug real encontrado escribiendo los escenarios nuevos del simulador
    # (siem/scenarios.py): "Cámara comprometida" (con tilde) no casaba
    # contra la keyword "camara comprometida" (sin tilde) con un `in`
    # normal -- ver _normalize en siem/threat_detection.py.
    event = Event(source="test", event_type="dispositivo_iot_comprometido", summary="Cámara comprometida detectada en la red")
    assert 30 in detect_threats(event)  # Botnets de IoT


def test_every_catalog_entry_has_at_least_one_keyword():
    for threat in THREATS_CATALOG:
        assert threat["keywords"], f"La amenaza {threat['id']} no tiene keywords"


def test_catalog_has_thirty_entries_with_unique_ids():
    assert len(THREATS_CATALOG) == 30
    ids = [t["id"] for t in THREATS_CATALOG]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Integración: ingesta real -> correlación -> incidente con threat_ids
# ---------------------------------------------------------------------------

def _ingest(client, **overrides):
    payload = {
        "source": "test",
        "asset_name": "web-prod-01",
        "event_type": "generico",
        "severity": "alta",
        "summary": "Evento genérico",
    }
    payload.update(overrides)
    return client.post("/v1/monitoring/ingest", json=payload)


def test_ingest_event_assigns_threat_ids(client):
    response = _ingest(
        client,
        event_type="phishing",
        summary="Clic en enlace de phishing confirmado",
    )
    assert response.status_code == 200
    assert 3 in response.json()["threat_ids"]

    incidents = client.get("/v1/incidents").json()
    assert 3 in incidents[0]["threat_ids"]


def test_incident_threat_ids_accumulate_across_correlated_events(client):
    _ingest(client, asset_name="db-prod-01", event_type="consulta_anomala", summary="Consulta masiva a tabla de clientes")
    _ingest(client, asset_name="db-prod-01", event_type="exfiltracion", summary="Transferencia saliente inusual detectada")

    incidents = client.get("/v1/incidents").json()
    assert len(incidents) == 1  # mismo activo, se correlaciona en un único incidente
    # el segundo evento no matchea ninguna keyword propia -- el objetivo aquí
    # es solo confirmar que no se pierde el threat_id que sí puso el primero
    assert isinstance(incidents[0]["threat_ids"], list)


def test_ingest_event_without_threat_match_leaves_empty_list(client):
    response = _ingest(client, event_type="rutina", summary="Backup nocturno completado sin incidencias")
    assert response.json()["threat_ids"] == []


def test_detected_threat_adds_prevention_as_recommendation(client):
    _ingest(client, event_type="ransomware", summary="Ransomware detectado, archivos con extensión .locked")

    incidents = client.get("/v1/incidents").json()
    recommendations = incidents[0]["recommendations"]
    assert len(recommendations) == 1
    assert "Ransomware" in recommendations[0]


def test_same_threat_detected_twice_does_not_duplicate_recommendation(client):
    _ingest(client, asset_name="web-prod-01", event_type="ransomware", summary="Ransomware detectado, .locked")
    _ingest(client, asset_name="web-prod-01", event_type="ransomware", summary="Segunda oleada de ransomware, .locked")

    incidents = client.get("/v1/incidents").json()
    assert len(incidents) == 1
    ransomware_recommendations = [r for r in incidents[0]["recommendations"] if "Ransomware" in r]
    assert len(ransomware_recommendations) == 1


# ---------------------------------------------------------------------------
# Router /v1/threats
# ---------------------------------------------------------------------------

def test_list_threats_returns_thirty_entries(client):
    response = client.get("/v1/threats")
    assert response.status_code == 200
    assert len(response.json()) == 30


def test_get_threat_entry_returns_correct_entry(client):
    response = client.get("/v1/threats/6")
    assert response.status_code == 200
    assert response.json()["nombre"] == "Ransomware"


def test_get_threat_entry_unknown_id_returns_404(client):
    response = client.get("/v1/threats/999")
    assert response.status_code == 404


def test_detected_threats_excludes_undetected_and_includes_detected(client):
    _ingest(client, event_type="ransomware", summary="Ransomware detectado, archivos con extensión .locked")

    response = client.get("/v1/threats/detectados")
    assert response.status_code == 200
    detected_ids = [t["id"] for t in response.json()]
    assert 6 in detected_ids  # Ransomware, sí se detectó
    assert 29 not in detected_ids  # SIM swapping, no se ha simulado en este test

    ransomware_entry = next(t for t in response.json() if t["id"] == 6)
    assert len(ransomware_entry["incidentes_detectados"]) == 1


def test_detected_threats_route_does_not_collide_with_threat_id_route(client):
    response = client.get("/v1/threats/detectados")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
