"""Tests de los módulos nuevos del SOC: ingesta genérica, correlación,
incidentes, chat de IA y automatización. El store ya no es un singleton en
memoria (era `siem.store.store`, borrado a mano entre tests) — ahora es
SQLite vía la misma base de pruebas en memoria de conftest.py, aislada por
test automáticamente por la fixture `_fresh_database`.
"""


def _ingest_event(client, asset_name="web-prod-01", severity="alta", summary="Login sospechoso"):
    payload = {
        "source": "test",
        "asset_name": asset_name,
        "event_type": "auth_anomaly",
        "severity": severity,
        "summary": summary,
    }
    return client.post("/v1/monitoring/ingest", json=payload)


def test_ingest_event_creates_incident(client):
    response = _ingest_event(client)
    assert response.status_code == 200

    incidents = client.get("/v1/incidents").json()
    assert len(incidents) == 1
    assert incidents[0]["affected_assets"] == ["web-prod-01"]


def test_correlation_groups_same_asset_into_one_incident(client):
    _ingest_event(client, asset_name="web-prod-01", summary="Evento 1")
    _ingest_event(client, asset_name="web-prod-01", summary="Evento 2")

    incidents = client.get("/v1/incidents").json()
    assert len(incidents) == 1
    assert len(incidents[0]["event_ids"]) == 2


def test_different_assets_create_different_incidents(client):
    _ingest_event(client, asset_name="web-prod-01")
    _ingest_event(client, asset_name="db-prod-01")

    incidents = client.get("/v1/incidents").json()
    assert len(incidents) == 2


def test_overview_reports_open_alerts_and_risk(client):
    _ingest_event(client, severity="critica")
    overview = client.get("/v1/monitoring/overview").json()
    assert overview["alertas_abiertas"] == 1
    assert overview["riesgo_global"] > 0
    assert overview["eventos_ultimo_minuto"] >= 1


def test_incident_status_update(client):
    _ingest_event(client)
    incident_id = client.get("/v1/incidents").json()[0]["id"]

    response = client.patch(f"/v1/incidents/{incident_id}", json={"status": "resuelto"})
    assert response.status_code == 200
    assert response.json()["status"] == "resuelto"

    overview = client.get("/v1/monitoring/overview").json()
    assert overview["alertas_abiertas"] == 0


def test_resolve_sets_resolved_at_and_reopen_clears_it(client):
    _ingest_event(client)
    incident = client.get("/v1/incidents").json()[0]
    assert incident["resolved_at"] is None

    resolved = client.patch(f"/v1/incidents/{incident['id']}", json={"status": "resuelto"}).json()
    assert resolved["resolved_at"] is not None

    # Reabrir invalida el tiempo de resolución: aún no está resuelto de verdad.
    reopened = client.patch(f"/v1/incidents/{incident['id']}", json={"status": "abierto"}).json()
    assert reopened["resolved_at"] is None


def test_delete_resolved_incident(client):
    _ingest_event(client)
    incident_id = client.get("/v1/incidents").json()[0]["id"]
    client.patch(f"/v1/incidents/{incident_id}", json={"status": "resuelto"})

    response = client.delete(f"/v1/incidents/{incident_id}")
    assert response.status_code == 204
    assert client.get("/v1/incidents").json() == []


def test_delete_unresolved_incident_is_rejected(client):
    _ingest_event(client)
    incident_id = client.get("/v1/incidents").json()[0]["id"]

    response = client.delete(f"/v1/incidents/{incident_id}")
    assert response.status_code == 409
    # Sigue existiendo: la eliminación exige resolver primero.
    assert len(client.get("/v1/incidents").json()) == 1


def test_delete_missing_incident_returns_404(client):
    assert client.delete("/v1/incidents/INC-inexistente").status_code == 404


def test_explain_incident_without_ai_key_falls_back_to_rules(client):
    _ingest_event(client)
    incident_id = client.get("/v1/incidents").json()[0]["id"]

    response = client.post(f"/v1/incidents/{incident_id}/explain")
    assert response.status_code == 200
    body = response.json()
    assert "reglas" in body["proveedor_ia"]
    assert body["explicacion"]


def test_ai_chat_without_key_returns_fallback_not_error(client):
    response = client.post("/v1/ai/chat", json={"message": "¿qué prioridad tiene esto?"})
    assert response.status_code == 200
    assert response.json()["respuesta"]


def test_automation_requires_confirmation(client):
    rule = client.post(
        "/v1/automation/rules",
        json={"name": "Notificar crítico", "trigger": "severity>=critica", "action": "notificar"},
    ).json()

    unconfirmed = client.post(f"/v1/automation/rules/{rule['id']}/execute")
    assert unconfirmed.json()["ejecutado"] is False

    confirmed = client.post(f"/v1/automation/rules/{rule['id']}/execute?confirm=true")
    assert confirmed.json()["ejecutado"] is True


def test_executive_panel_reflects_critical_incidents(client):
    _ingest_event(client, severity="critica", summary="Ransomware detectado")
    panel = client.get("/v1/reports/executive").json()
    assert panel["incidentes_criticos_abiertos"] == 1


def test_timeseries_returns_buckets_for_each_granularity(client):
    _ingest_event(client, severity="critica")
    for granularity in ("hour", "day", "month", "year"):
        response = client.get(f"/v1/monitoring/timeseries?granularity={granularity}")
        assert response.status_code == 200
        data = response.json()
        assert data["granularity"] == granularity
        assert len(data["buckets"]) >= 1
        assert data["buckets"][-1]["eventos"] >= 1
        assert data["buckets"][-1]["criticos"] >= 1
