"""Verifica que demosiem.praxialabs.com redirige a la demo pública
(2026-09-04, siem/main.py::demo_host_redirect_middleware).

Motivo: ese hostname del túnel Cloudflare quedó publicado sin política de
Access -- servía el dashboard real sin gate. Se reutiliza redirigiendo todo
su tráfico a /demo/dashboard en vez de tocar la config de Cloudflare.
"""
from fastapi.testclient import TestClient

from siem.main import create_app


def test_demosiem_redirige_a_demo_dashboard():
    app = create_app()
    client = TestClient(app, follow_redirects=False)

    resp = client.get("/", headers={"host": "demosiem.praxialabs.com"})

    assert resp.status_code == 302
    assert resp.headers["location"] == "https://siem.praxialabs.com/demo/dashboard"


def test_demosiem_redirige_independientemente_de_la_ruta_pedida():
    app = create_app()
    client = TestClient(app, follow_redirects=False)

    resp = client.get("/v1/monitoring/overview", headers={"host": "demosiem.praxialabs.com"})

    assert resp.status_code == 302
    assert resp.headers["location"] == "https://siem.praxialabs.com/demo/dashboard"


def test_otros_hosts_no_se_redirigen():
    app = create_app()
    client = TestClient(app, follow_redirects=False)

    resp = client.get("/demo/dashboard", headers={"host": "siem.praxialabs.com"})

    assert resp.status_code == 200
