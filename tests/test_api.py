"""Tests del pipeline de tickets (SQLite, siem/router/api.py).

La base de datos de pruebas (en memoria, aislada de siem.db) y el cliente
viven en conftest.py, compartidos con test_incidents.py.
"""


def sample_payload():
    return {
        "ticket_id": "TEST-123",
        "status": "NUEVO",
        "service": "test-service",
        "description": "Test description",
        "priority": "HIGH",
    }


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_ingest_jira(client):
    payload = sample_payload()
    response = client.post("/v1/ingest/jira", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["ticket_id"] == payload["ticket_id"]
    assert data["status"] == payload["status"]


def test_metrics_initial(client):
    response = client.get("/v1/metrics")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["summary"]["total_tickets"] == 0
    assert isinstance(json_data["recent_tickets"], list)


def test_metrics_reflects_ingested_ticket(client):
    payload = sample_payload()
    client.post("/v1/ingest/jira", json=payload)
    response = client.get("/v1/metrics")
    data = response.json()
    assert data["summary"]["total_tickets"] == 1
    assert data["recent_tickets"][0]["external_id"] == payload["ticket_id"]
    assert data["recent_tickets"][0]["provider"] == payload["service"]
