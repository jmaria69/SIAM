"""Tests del scheduler de campañas (siem/campaign_scheduler.py): envío
automático cuando `starts_at` vence.

Se testea `list_due_campaigns` (store) y `run_due_campaigns_once`
(scheduler) de forma síncrona y directa, contra una base en memoria propia
de este archivo (mismo patrón que tests/test_simulator.py) -- no hace
falta pasar por HTTP ni por el motor de IA para probar la lógica de "qué
está vencido y listo para enviarse". El bucle real (`run_scheduler_loop`,
que sí espera con `asyncio.sleep`) se deja fuera a propósito, mismo
criterio que con el simulador de crisis: los tests no dependen de tiempo
real ni de servicios externos.

`run_due_campaigns_once` recibe aquí un `Settings(SMTP_HOST=None)`
explícito en vez de dejar que use el `get_settings()` real cacheado --
si no, en cuanto alguien configure SMTP de verdad en `.env`, este test
intentaría una conexión SMTP real en cada `pytest`.
"""
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from siem.campaign_scheduler import run_due_campaigns_once
from siem.config import Settings
from siem.database import Base
from siem.models import Campaign, CampaignTarget
from siem.store import SiemStore

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_Session = sessionmaker(bind=_engine)
_TEST_SETTINGS = Settings(AI_PROVIDER="none", SMTP_HOST=None)


def setup_function(_):
    Base.metadata.create_all(bind=_engine)


def teardown_function(_):
    Base.metadata.drop_all(bind=_engine)


def _make_campaign(name, starts_at=None, content=None) -> Campaign:
    return Campaign(
        name=name,
        targets=[CampaignTarget(name="Ana Pérez", email="ana@empresa.com", department="finanzas")],
        starts_at=starts_at,
        content=content,
    )


def test_list_due_campaigns_excludes_future_launch():
    db = _Session()
    try:
        store = SiemStore(db)
        store.add_campaign(
            _make_campaign("Futura", starts_at=datetime.utcnow() + timedelta(days=1), content="listo")
        )
        assert store.list_due_campaigns() == []
    finally:
        db.close()


def test_list_due_campaigns_excludes_campaign_without_content():
    db = _Session()
    try:
        store = SiemStore(db)
        store.add_campaign(
            _make_campaign("Vencida sin contenido", starts_at=datetime.utcnow() - timedelta(minutes=5))
        )
        assert store.list_due_campaigns() == []
    finally:
        db.close()


def test_list_due_campaigns_excludes_campaign_without_starts_at():
    db = _Session()
    try:
        store = SiemStore(db)
        store.add_campaign(_make_campaign("Sin fecha", content="listo"))
        assert store.list_due_campaigns() == []
    finally:
        db.close()


def test_list_due_campaigns_includes_overdue_ready_campaign():
    db = _Session()
    try:
        store = SiemStore(db)
        campaign = _make_campaign(
            "Lista para enviar", starts_at=datetime.utcnow() - timedelta(minutes=5), content="listo"
        )
        store.add_campaign(campaign)
        due = store.list_due_campaigns()
        assert [c.id for c in due] == [campaign.id]
    finally:
        db.close()


def test_run_due_campaigns_once_sends_and_marks_active_then_stops_resending():
    db = _Session()
    try:
        store = SiemStore(db)
        campaign = _make_campaign(
            "Auto-envío", starts_at=datetime.utcnow() - timedelta(minutes=5), content="listo"
        )
        store.add_campaign(campaign)

        resultados = run_due_campaigns_once(store, _TEST_SETTINGS)
        assert len(resultados) == 1
        assert resultados[0]["campaign_id"] == campaign.id
        assert resultados[0]["smtp_configurado"] is False
        assert resultados[0]["omitidos"] == 1  # sin SMTP configurado en _TEST_SETTINGS

        refreshed = store.get_campaign(campaign.id)
        assert refreshed.status.value == "activa"

        # Un segundo tick no debe reenviarla -- ya no está en borrador.
        assert run_due_campaigns_once(store, _TEST_SETTINGS) == []
    finally:
        db.close()


def test_run_due_campaigns_once_with_nothing_due_returns_empty_list():
    db = _Session()
    try:
        store = SiemStore(db)
        assert run_due_campaigns_once(store, _TEST_SETTINGS) == []
    finally:
        db.close()
