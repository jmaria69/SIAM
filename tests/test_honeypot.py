"""Panel señuelo de Active Defense (siem/router/honeypot.py). Ver su
docstring: fuera de /v1/* a propósito (sin X-SIAM-API-Key), cada visita se
registra como Event(source="honeypot") por el mismo pipeline que
siem/router/waf.py."""
def test_honeypot_page_loads_without_api_key(client):
    resp = client.get("/admin")
    assert resp.status_code == 200
    assert "usuario" in resp.text.lower()


def test_honeypot_view_logs_high_severity_event(client, db_session):
    from siem.db_models import EventDB

    client.get("/admin")

    rows = db_session.query(EventDB).filter(EventDB.source == "honeypot").all()
    assert len(rows) == 1
    assert rows[0].severity == "alta"
    assert rows[0].raw_payload["usuario_probado"] is None


def test_honeypot_login_attempt_logs_critical_event_with_credentials(client, db_session):
    from siem.db_models import EventDB

    resp = client.post("/admin", data={"usuario": "admin", "password": "1234"})
    assert resp.status_code == 200
    assert "incorrectos" in resp.text.lower()

    rows = db_session.query(EventDB).filter(EventDB.source == "honeypot").all()
    assert len(rows) == 1
    assert rows[0].severity == "critica"
    assert rows[0].raw_payload["usuario_probado"] == "admin"
    assert rows[0].raw_payload["password_probada"] == "1234"


def test_honeypot_attempt_creates_incident(client, db_session):
    from siem.db_models import IncidentDB

    client.post("/admin", data={"usuario": "root", "password": "toor"})

    incidents = db_session.query(IncidentDB).all()
    assert len(incidents) == 1
