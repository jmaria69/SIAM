"""Verifica que /v1/* exige X-SIAM-API-Key cuando SIAM_API_KEY está
configurada (2026-09-03, siem/main.py::api_key_middleware).

Motivo: el backend estaba expuesto sin ninguna autenticación -- ver el
comentario en siem/config.py junto a SIAM_API_KEY. Mismo patrón que
test_docs_gating.py: cada test construye su propia app con create_app(...)
porque docs_url/api_key_middleware se fijan en el constructor, no en tiempo
de request.
"""
import pytest
from fastapi.testclient import TestClient

from siem.config import Settings
from siem.main import create_app


def test_v1_sin_clave_devuelve_401_si_hay_api_key_configurada():
    app = create_app(Settings(SIAM_API_KEY="secreta"))
    client = TestClient(app)

    resp = client.get("/v1/metrics/scalability")

    assert resp.status_code == 401


def test_v1_con_clave_incorrecta_devuelve_401():
    app = create_app(Settings(SIAM_API_KEY="secreta"))
    client = TestClient(app)

    resp = client.get(
        "/v1/metrics/scalability", headers={"X-SIAM-API-Key": "incorrecta"}
    )

    assert resp.status_code == 401


def test_v1_con_clave_correcta_pasa():
    app = create_app(Settings(SIAM_API_KEY="secreta"))
    client = TestClient(app)

    resp = client.get(
        "/v1/metrics/scalability", headers={"X-SIAM-API-Key": "secreta"}
    )

    assert resp.status_code == 200


def test_v1_sin_api_key_configurada_no_exige_cabecera():
    # Desarrollo local sin SIAM_API_KEY en .env: no debe romper el flujo
    # existente de nadie -- fail-open solo aplica fuera de producción.
    app = create_app(Settings(SIAM_API_KEY=None))
    client = TestClient(app)

    resp = client.get("/v1/metrics/scalability")

    assert resp.status_code == 200


def test_produccion_sin_api_key_aborta_arranque():
    with pytest.raises(RuntimeError):
        create_app(Settings(ENVIRONMENT="production", SIAM_API_KEY=None))
