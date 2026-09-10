"""Endpoints de solo-lectura del honeypot en la demo (2026-09-10).

El panel 🍯 Honeypot de /demo/dashboard lee las sesiones del señuelo
sembradas a mano (siem/demo_seed.py) vía /demo/v1/honeypot/sessions. Al
igual que los leads, estas rutas son públicas (no piden X-SIAM-API-Key).

Al contrario que la demo real (que usa el siam_demo.db de disco), estos
tests sustituyen get_demo_store por una base en memoria sembrada con
seed_demo_data(), para no tocar ni depender del fichero real del proyecto.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from siem.database import Base
from siem.demo_seed import seed_demo_data
from siem.main import app
from siem.router.demo import get_demo_store
from siem.store import SiemStore

_demo_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_DemoSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_demo_engine)


@pytest.fixture(autouse=True)
def _isolated_demo_store():
    Base.metadata.create_all(bind=_demo_engine)
    db = _DemoSessionLocal()
    try:
        seed_demo_data(SiemStore(db))

        def _override():
            yield SiemStore(db)

        app.dependency_overrides[get_demo_store] = _override
        yield
    finally:
        db.close()
        app.dependency_overrides.pop(get_demo_store, None)
        Base.metadata.drop_all(bind=_demo_engine)


def test_demo_honeypot_sessions_sin_api_key():
    client = TestClient(app)
    resp = client.get("/demo/v1/honeypot/sessions")
    assert resp.status_code == 200
    payload = resp.json()

    # Tres recorridos curados (explorer, bruteforce, methodical). Los
    # "honeypot.interaction" del seed de métricas quedan FUERA del rollup
    # (SESSION_EVENT_TYPES en siem/honeypot_sessions.py).
    assert payload["stats"]["total_sessions"] == 3
    # Credenciales del seed curado: explorer 2 + bruteforce 3 + methodical 1.
    assert payload["stats"]["credentials_captured"] == 6
    assert {s["session_id"] for s in payload["sessions"]} == {
        "sis-demo-explorer", "sis-demo-bruteforce", "sis-demo-methodical",
    }


def test_demo_honeypot_session_detail_curada():
    client = TestClient(app)
    resp = client.get("/demo/v1/honeypot/sessions/sis-demo-explorer")
    assert resp.status_code == 200
    session = resp.json()["session"]

    assert session["depth"] == 3  # llega al final del señuelo (upload)
    assert session["duration_seconds"] >= 100  # ~105s
    assert [c["usuario"] for c in session["credentials"]] == ["admin", "root"]
    assert session["steps"] == ["phpmyadmin", "config", "upload"]


def test_demo_honeypot_session_bruteforce_sin_js():
    client = TestClient(app)
    resp = client.get("/demo/v1/honeypot/sessions/sis-demo-bruteforce")
    session = resp.json()["session"]

    # Matraz de credenciales: como no ejecuta JS, solo martillea el login:
    # 3 intentos, ningún paso del señuelo en profundidad.
    assert session["login_attempts"] == 3
    assert session["depth"] == 1
    assert session["steps"] == []


def test_demo_honeypot_session_detail_404():
    client = TestClient(app)
    assert client.get("/demo/v1/honeypot/sessions/desconocida").status_code == 404