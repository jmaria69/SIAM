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
    # Vista: solo se rellena usuario_probado/password_probada en los intentos
    # de login, no en eventos de navegación (siem/router/honeypot.py::_log).
    assert "usuario_probado" not in rows[0].raw_payload
    assert rows[0].raw_payload["session_id"].startswith("sis-")


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


def test_honeypot_beacon_logs_step_event(client, db_session):
    from siem.db_models import EventDB

    # Beacon del señuelo en profundidad (JS client-side), sin credenciales.
    client.post("/admin", data={"step": "phpmyadmin", "elapsed_ms": "42000"})

    rows = db_session.query(EventDB).filter(EventDB.source == "honeypot").all()
    assert len(rows) == 1
    assert rows[0].event_type == "honeypot.step"
    assert rows[0].severity == "media"
    assert rows[0].raw_payload["step"] == "phpmyadmin"
    assert rows[0].raw_payload["elapsed_ms"] == 42000


def test_honeypot_cookie_une_toda_la_visita(client, db_session):
    from siem.db_models import EventDB

    resp = client.get("/admin")
    rows = db_session.query(EventDB).filter(EventDB.source == "honeypot").all()
    assert len(rows) == 1
    sid = rows[0].raw_payload["session_id"]
    assert sid and sid.startswith("sis-")

    # La cookie se entrega y coincide con el session_id del evento de la vista.
    set_cookie = resp.headers.get("set-cookie") or ""
    assert sid in set_cookie

    # Los siguientes POST (el TestClient reenvía la cookie automáticamente)
    # heredan la MISMA sesión.
    client.post("/admin", data={"usuario": "admin", "password": "x"})
    client.post("/admin", data={"step": "upload", "elapsed_ms": "90000"})
    rows = db_session.query(EventDB).filter(EventDB.source == "honeypot").all()
    assert [r.raw_payload["session_id"] for r in rows] == [sid, sid, sid]


def test_honeypot_sessions_api_rebuilds_journey(client):
    # Una visita completa: vista + login fallido + dos beacons.
    client.get("/admin")
    client.post("/admin", data={"usuario": "admin", "password": "1234"})
    client.post("/admin", data={"step": "phpmyadmin", "elapsed_ms": "30000"})
    client.post("/admin", data={"step": "upload", "elapsed_ms": "60000"})

    resp = client.get("/v1/honeypot/sessions")
    assert resp.status_code == 200
    payload = resp.json()

    stats = payload["stats"]
    assert stats["total_sessions"] == 1
    assert stats["login_attempts"] == 1
    assert stats["credentials_captured"] == 1
    assert stats["avg_depth"] == 3

    session = payload["sessions"][0]
    assert session["event_count"] == 4
    assert session["login_attempts"] == 1
    assert session["depth"] == 3  # upload = nivel 3 del señuelo en profundidad
    assert session["steps"] == ["phpmyadmin", "upload"]
    assert [e["event_type"] for e in session["events"]] == [
        "honeypot.view",
        "honeypot.login_attempt",
        "honeypot.step",
        "honeypot.step",
    ]
    assert session["credentials"][0]["usuario"] == "admin"
    assert session["credentials"][0]["password"] == "1234"
    # El recorrido llega ordenado y con el elapsed_ms del beacon.
    assert session["events"][2]["step"] == "phpmyadmin"
    assert session["events"][2]["elapsed_ms"] == 30000


def test_honeypot_sessions_api_filters_by_ip(client, db_session):
    from siem.db_models import EventDB

    client.get("/admin")
    # En TestClient el host de la petición es "testclient" -- leemos la IP
    # realmente registrada en vez de asumir localhost.
    ip = db_session.query(EventDB).filter(EventDB.source == "honeypot").one().raw_payload["client_ip"]

    resp = client.get("/v1/honeypot/sessions?ip=10.0.0.99")
    assert resp.status_code == 200
    assert resp.json()["stats"]["total_sessions"] == 0

    resp = client.get(f"/v1/honeypot/sessions?ip={ip}")
    assert resp.json()["stats"]["total_sessions"] == 1


def test_honeypot_session_detail(client):
    client.get("/admin")
    client.post("/admin", data={"step": "config", "elapsed_ms": "5000"})

    listing = client.get("/v1/honeypot/sessions").json()
    session_id = listing["sessions"][0]["session_id"]

    detail = client.get(f"/v1/honeypot/sessions/{session_id}")
    assert detail.status_code == 200
    assert detail.json()["session"]["event_count"] == 2
    assert detail.json()["session"]["depth"] == 2  # config = nivel 2

    assert client.get("/v1/honeypot/sessions/no-existe").status_code == 404
