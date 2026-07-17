"""Verifica el gating de /docs, /redoc y /openapi.json por entorno
(2026-07-05, siem/main.py::create_app).

No reutiliza la fixture `client` de conftest.py a propósito: esa fixture
importa el `app` ya construido a nivel de módulo con la config por defecto
(ENVIRONMENT=development), fijada en el momento del import de siem.main.
app.dependency_overrides[get_settings] NO sirve aquí -- solo intercepta
Depends(get_settings) resuelto en tiempo de request, y docs_url/redoc_url/
openapi_url ya se consumieron en el constructor de FastAPI mucho antes de
que exista ninguna request. Por eso cada test construye su propia app con
create_app(Settings(ENVIRONMENT=...)) directamente, igual que
test_campaign_scheduler.py evita depender del singleton de settings cacheado.
"""
from fastapi.testclient import TestClient

from siem.config import Settings
from siem.main import create_app


def test_docs_enabled_by_default_in_development():
    app = create_app(Settings(ENVIRONMENT="development"))
    client = TestClient(app)

    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_docs_disabled_in_production():
    app = create_app(Settings(ENVIRONMENT="production"))
    client = TestClient(app)

    # FastAPI responde 404 real (la ruta no existe) cuando docs_url=None,
    # no un 401/403 que de paso confirmaría que la ruta sí está montada.
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_default_environment_is_development():
    # Settings() sin argumentos (comportamiento real si alguien no pone
    # ENVIRONMENT en su .env) debe dejar docs activos -- default seguro
    # para desarrollo local, no un "fail closed" sorpresa para nadie que
    # actualice el código sin tocar su .env.
    app = create_app(Settings(AI_PROVIDER="none", SMTP_HOST=None))
    client = TestClient(app)

    assert client.get("/docs").status_code == 200
