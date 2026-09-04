"""Fixtures compartidas entre test_api.py (tickets Jira) y test_incidents.py
(eventos/incidentes del SOC) — ambos viven en el mismo siem.db real desde
que se persistió siem/store.py en SQLite, así que comparten la misma base
de pruebas en memoria, nueva en cada test.

Actualizado 2026-07-05: import movido de `siam.*` a `siem.*` tras el rename
de paquete (ver CLAUDE.md). Estos tests ahora validan el paquete `siem/`
activo, no el `siam/` original (que queda huérfano en disco).
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import siem.correlation as correlation
from siem.config import Settings, get_settings
from siem.database import Base, get_db
from siem.main import app

# StaticPool es imprescindible: sqlite:///:memory: crea una base nueva por
# cada conexión, y TestClient atiende las peticiones en un hilo distinto al
# de pytest. Sin StaticPool, las tablas se crean en una conexión/hilo y las
# peticiones ven una base en memoria distinta y vacía -> "no such table".
engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


def _override_get_settings() -> Settings:
    # Bug real (2026-07-03): sin este override, get_settings() lee el .env
    # REAL del proyecto (AI_PROVIDER=local -> Ollama en 127.0.0.1:11434).
    # test_explain_incident_without_ai_key_falls_back_to_rules asume que no
    # hay proveedor de IA configurado, pero contra el .env real intentaba una
    # llamada HTTP de verdad al LLM local -- si no respondía (o no había
    # timeout), pytest se quedaba colgado ahí, no fallaba. Se fuerza
    # AI_PROVIDER="none" solo para tests, igual que get_db ya se fuerza a
    # SQLite en memoria: los tests no deben depender de servicios externos.
    #
    # Mismo criterio aplicado preventivamente a SMTP_HOST (campañas de
    # concienciación, añadidas después): si José configura alguna vez SMTP_*
    # de verdad en .env, sin este override los tests de campañas
    # intentarían enviar emails reales en cada `pytest`. Se fuerza a None
    # aquí para que la aislación no dependa de que .env esté vacío.
    #
    # ALERT_EMAIL_TO (alerta de incidente nuevo, siem/notifications.py)
    # sigue el mismo criterio: se fuerza a None aunque el .env real lo
    # tenga configurado.
    #
    # CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID (2026-09-04, conector real de
    # Active Defense, siem/cloudflare_firewall.py): mismo criterio otra vez,
    # y aquí el coste de un fallo es mucho peor que un LLM o un SMTP que se
    # cuelgan -- sin este override, cualquier test que dispare /respond con
    # BLOCK/CHALLENGE ejecuta una llamada de escritura DE VERDAD contra el
    # firewall de producción (repro real 2026-09-04: test_respond_requires_
    # confirmation_then_executes creó una IP Access Rule real para 9.9.9.9 en
    # la zona de Cloudflare). Se fuerza a None aquí; los tests que necesitan
    # el conector real lo activan explícitamente vía
    # _enable_module_with_cloudflare() en tests/test_active_defense.py, con
    # la llamada HTTP siempre mockeada.
    return Settings(
        AI_PROVIDER="none", SMTP_HOST=None, ALERT_EMAIL_TO=None,
        CLOUDFLARE_API_TOKEN=None, CLOUDFLARE_ZONE_ID=None,
    )


app.dependency_overrides[get_settings] = _override_get_settings


@pytest.fixture(autouse=True)
def _isolate_correlation_settings(monkeypatch):
    # siem/correlation.py::correlate_event llama a get_settings() DIRECTAMENTE
    # (no vía Depends), así que dependency_overrides de arriba no lo cubre --
    # sin este parche, cada test que crea un incidente (la mayoría de
    # test_incidents.py, test_threat_detection.py, test_killchain.py...)
    # leería el .env real y, con SMTP + ALERT_EMAIL_TO configurados de
    # verdad, dispararía un envío de email real por Hostinger en cada
    # `pytest`.
    monkeypatch.setattr(correlation, "get_settings", _override_get_settings)


@pytest.fixture(autouse=True)
def _fresh_database():
    """Tablas nuevas antes de cada test (tickets + assets/events/incidents/
    iocs/automation_rules/reports), borradas después. Aísla completamente
    cada test entre sí y del siem.db real del proyecto."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    """Sesión directa a la BD de test, para tests que necesitan comprobar
    persistencia (p.ej. que un honeypot NO escribió fila) sin pasar por un
    endpoint de lectura."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
