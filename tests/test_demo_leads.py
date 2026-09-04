"""Ruta pública de captación de demo (siem/router/demo.py, 2026-09-03).

Cubre: la página y el endpoint son alcanzables sin X-SIAM-API-Key aunque
SIAM_API_KEY esté configurada (tienen que serlo -- las visita un prospecto
anónimo desde el navegador), el honeypot no persiste ni notifica, y el
lead válido se guarda en BD.
"""
from fastapi.testclient import TestClient

from siem.config import Settings
from siem.database import Base, engine
from siem.db_models import DemoLeadDB
from siem.main import create_app


def test_get_demo_landing_no_requiere_api_key():
    app = create_app(Settings(SIAM_API_KEY="secreta"))
    client = TestClient(app)

    resp = client.get("/demo")

    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_post_demo_request_no_requiere_api_key_y_persiste(client):
    resp = client.post(
        "/demo/request",
        json={
            "name": "Ana Prospecto",
            "email": "ana@ejemplo.com",
            "phone": "+34600000000",
            "company": "Ejemplo SL",
            "message": "Quiero ver el SOC con datos reales",
        },
    )

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_post_demo_request_honeypot_no_persiste(client, db_session):
    resp = client.post(
        "/demo/request",
        json={
            "name": "Bot",
            "email": "bot@ejemplo.com",
            "phone": "000",
            "website": "http://spam.example",
        },
    )

    assert resp.status_code == 200
    assert db_session.query(DemoLeadDB).count() == 0


def test_post_demo_request_email_invalido_devuelve_422(client):
    resp = client.post(
        "/demo/request",
        json={"name": "X", "email": "no-es-un-email", "phone": "123"},
    )

    assert resp.status_code == 422
