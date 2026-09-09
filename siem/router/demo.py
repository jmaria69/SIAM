"""Ruta pública de captación de demo (2026-09-03).

Contexto: siem.praxialabs.com queda detrás de Cloudflare Access restringido
al email del propietario. Para enseñar el SOC a un prospecto con datos
REALES sin abrir esa política a cualquiera, el flujo es: (1) esta página
pública, fuera de Access, donde deja nombre/email/teléfono; (2) un email
avisa a José (reutiliza `notificar_incidente`/`enviar_email`, mismo SMTP);
(3) José revisa manualmente y, si procede, añade el email del prospecto a
la política de Access de un hostname aparte (p.ej. demo.siem.praxialabs.com)
que apunta al mismo backend real. Sin verificación automática de
teléfono/SMS a propósito (decisión explícita: sin integraciones nuevas).

Vive fuera del prefijo /v1/ para no depender de api_key_middleware (ver
siem/main.py) — es una petición anónima desde el navegador de un
prospecto, no puede llevar la cabecera X-SIAM-API-Key.
"""
import datetime as dt
import logging
import os
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from siem.config import Settings, get_settings
from siem.database import Base, get_db
from siem.db_models import DemoLeadDB
from siem.demo_seed import seed_demo_data
from siem.models import Asset, Event, Incident, IncidentStatus
from siem.notifications import enviar_email
from siem.router.incidents import IncidentUpdate
from siem.router.incidents import explain_incident as _incidents_explain
from siem.router.incidents import get_incident as _incidents_get
from siem.router.incidents import list_incidents as _incidents_list
from siem.router.incidents import reconstruct_kill_chain as _incidents_kill_chain
from siem.router.incidents import update_incident as _incidents_update
from siem.router.active_defense import metrics as _active_defense_metrics
from siem.router.monitoring import get_overview as _monitoring_overview
from siem.router.monitoring import get_timeseries as _monitoring_timeseries
from siem.router.monitoring import ingest_event as _monitoring_ingest
from siem.router.monitoring import list_assets as _monitoring_assets
from siem.router.reports import executive_panel as _reports_executive
from siem.router.course_cybersecurity import router as pyme_router
from siem.store import SiemStore

logger = logging.getLogger("siem.demo")

router = APIRouter(tags=["demo"])

# ---------------------------------------------------------------------------
# Dashboard de ejemplo (/demo/dashboard): reutiliza el código real de los
# routers monitoring.py/incidents.py (llamándolos como funciones normales,
# no vía HTTP) pero apuntado a `siam_demo.db` -- una base SQLite SEPARADA
# de la real, sembrada con incidentes inventados (siem/demo_seed.py) -- y a
# `Settings(AI_PROVIDER="none")`, para que un visitante anónimo nunca vea
# datos de cliente reales ni dispare una llamada real al Ollama del usuario.
#
# Deliberadamente NO se monta monitoring_router completo: sus endpoints de
# simulador de crisis (`/simulate/{scenario_id}`, siem/simulator.py) abren
# su propia sesión contra `siem.database.SessionLocal` directamente (no vía
# Depends(get_db)), así que un dependency_override no los redirigiría --
# montarlos aquí escribiría eventos/incidentes de la demo en el `siam.db`
# REAL. Se exponen a mano solo los endpoints de solo-lectura/edición local
# que la demo necesita (overview, timeseries, assets, incidentes, ingest
# manual de eventos de prueba).
# ---------------------------------------------------------------------------
_DEMO_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "siam_demo.db")
)
_demo_engine = create_engine(f"sqlite:///{_DEMO_DB_PATH}", connect_args={"check_same_thread": False})
_DemoSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_demo_engine)


_demo_db_ready = False


def _get_demo_db():
    # Creación de tabla + sembrado perezosos, en el primer request real a
    # cualquier endpoint /demo/v1/* -- NO en el startup de la app principal:
    # main.py pasa un `lifespan` explícito a FastAPI(...), y con eso Starlette
    # ignora por completo los handlers @router.on_event("startup") (solo se
    # activan si la app no recibe `lifespan` propio), así que enganchar el
    # sembrado ahí nunca llegaría a ejecutarse. `seed_demo_data` ya es
    # idempotente por sí sola (no repite si ya hay incidentes); esta bandera
    # de módulo solo evita repetir el create_all+query en cada request.
    global _demo_db_ready
    if not _demo_db_ready:
        Base.metadata.create_all(bind=_demo_engine)
        seed_db = _DemoSessionLocal()
        try:
            seed_demo_data(SiemStore(seed_db))
        finally:
            seed_db.close()
        _demo_db_ready = True

    db = _DemoSessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_demo_store(db: Session = Depends(_get_demo_db)) -> SiemStore:
    return SiemStore(db)


def _demo_settings() -> Settings:
    return Settings(AI_PROVIDER="none")


class DemoLeadRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., min_length=3, max_length=200)
    phone: str = Field(..., min_length=3, max_length=40)
    company: str | None = Field(None, max_length=120)
    message: str | None = Field(None, max_length=500)
    website: str = ""  # honeypot: un humano lo deja vacío


@router.get("/demo", response_class=HTMLResponse)
async def get_demo_landing():
    if os.path.exists("demo_landing.html"):
        with open("demo_landing.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read(), headers={"Cache-Control": "no-store"})
    return HTMLResponse("<h1>demo_landing.html no encontrado</h1>", status_code=500)


@router.post("/demo/request")
async def post_demo_request(
    lead: DemoLeadRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    if lead.website:
        # Honeypot relleno -> bot. Respondemos 200 igualmente para no darle
        # ninguna señal de que fue detectado, pero no persistimos ni avisamos.
        return {"status": "ok"}

    if "@" not in lead.email:
        raise HTTPException(status_code=422, detail="Email inválido")

    record = DemoLeadDB(
        id=str(uuid.uuid4()),
        name=lead.name,
        email=lead.email,
        phone=lead.phone,
        company=lead.company,
        message=lead.message,
        created_at=dt.datetime.utcnow(),
    )
    db.add(record)
    db.commit()

    if settings.ALERT_EMAIL_TO:
        asunto = f"[SIAM] Nueva solicitud de demo real — {lead.name}"
        cuerpo = (
            f"<h2>Nueva solicitud de demo real</h2>"
            f"<p><b>Nombre:</b> {lead.name}<br>"
            f"<b>Email:</b> {lead.email}<br>"
            f"<b>Teléfono:</b> {lead.phone}<br>"
            f"<b>Empresa:</b> {lead.company or '—'}</p>"
            f"<p><b>Mensaje:</b><br>{lead.message or '—'}</p>"
            f"<p>Si procede, añade <code>{lead.email}</code> a la política "
            f"de Access del hostname de demo real.</p>"
        )
        enviado = enviar_email(settings, settings.ALERT_EMAIL_TO, asunto, cuerpo)
        record.notified = enviado
        db.commit()
    else:
        logger.info("ALERT_EMAIL_TO no configurado — lead de demo guardado sin notificación por email.")

    return {"status": "ok"}


@router.get("/demo/dashboard", response_class=HTMLResponse)
async def get_demo_dashboard():
    """Sirve el MISMO soc_dashboard.html que /dashboard -- el shim de fetch
    embebido detecta por la URL que está bajo /demo/dashboard y reescribe
    las llamadas a /v1/... hacia /demo/v1/... sin pedir X-SIAM-API-Key
    (ver soc_dashboard.html)."""
    if os.path.exists("soc_dashboard.html"):
        with open("soc_dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read(), headers={"Cache-Control": "no-store"})
    return HTMLResponse("<h1>soc_dashboard.html no encontrado</h1>", status_code=500)


@router.post("/demo/v1/monitoring/ingest", response_model=Event)
def demo_ingest_event(event: Event, store: SiemStore = Depends(get_demo_store)) -> Event:
    return _monitoring_ingest(event, store)


@router.get("/demo/v1/monitoring/overview")
def demo_overview(store: SiemStore = Depends(get_demo_store)) -> dict:
    return _monitoring_overview(store)


@router.get("/demo/v1/monitoring/timeseries")
def demo_timeseries(granularity: str = "day", store: SiemStore = Depends(get_demo_store)) -> dict:
    return _monitoring_timeseries(granularity, store)


@router.get("/demo/v1/monitoring/assets", response_model=list[Asset])
def demo_list_assets(store: SiemStore = Depends(get_demo_store)) -> list[Asset]:
    return _monitoring_assets(store)


@router.get("/demo/v1/incidents", response_model=list[Incident])
def demo_list_incidents(
    status: IncidentStatus | None = None, store: SiemStore = Depends(get_demo_store)
) -> list[Incident]:
    return _incidents_list(status, store)


@router.get("/demo/v1/incidents/{incident_id}", response_model=Incident)
def demo_get_incident(incident_id: str, store: SiemStore = Depends(get_demo_store)) -> Incident:
    return _incidents_get(incident_id, store)


@router.patch("/demo/v1/incidents/{incident_id}", response_model=Incident)
def demo_update_incident(
    incident_id: str, update: IncidentUpdate, store: SiemStore = Depends(get_demo_store)
) -> Incident:
    return _incidents_update(incident_id, update, store)


@router.post("/demo/v1/incidents/{incident_id}/explain")
def demo_explain_incident(incident_id: str, store: SiemStore = Depends(get_demo_store)) -> dict:
    return _incidents_explain(incident_id, store, _demo_settings())


@router.post("/demo/v1/incidents/{incident_id}/kill-chain")
def demo_kill_chain(incident_id: str, store: SiemStore = Depends(get_demo_store)) -> dict:
    return _incidents_kill_chain(incident_id, store, _demo_settings())


@router.get("/demo/v1/reports/executive")
def demo_executive_panel(store: SiemStore = Depends(get_demo_store)) -> dict:
    return _reports_executive(store)


# ---------------------------------------------------------------------------
# Praxia Active Defense: SOLO se expone /metrics (lectura pura sobre la base
# de datos de la demo, ver store.attack_metrics()). El resto del módulo
# (/overview, /respond, /blacklist, /whitelist) se deja fuera a propósito:
# /respond decide si ejecuta una acción REAL contra Cloudflare mirando
# `settings.CLOUDFLARE_API_TOKEN` (la configuración global de verdad, no la
# base de datos separada de la demo) -- un visitante anónimo podría acabar
# creando una IP Access Rule real en la zona de producción. La pestaña
# "⚔️ Praxia Active Defense" sigue oculta en /demo/dashboard (su gating usa
# /status, que aquí no existe a propósito); solo "📊 Métricas de ataques" se
# activa para el modo demo (ver soc_dashboard.html::IS_DEMO).
# ---------------------------------------------------------------------------
@router.get("/demo/v1/active-defense/metrics")
def demo_active_defense_metrics(
    date_from: str | None = None, date_to: str | None = None, store: SiemStore = Depends(get_demo_store),
) -> dict:
    return _active_defense_metrics(date_from=date_from, date_to=date_to, store=store)


# /demo/v1/pyme/* -- el motor de Ciberseguridad PYME es un conjunto de
# calculadoras sin estado (sin Depends(get_db) ni Depends(get_store), ver
# siem/router/course_cybersecurity.py), así que se reutiliza tal cual, sin
# ninguna base de datos de por medio.
router.include_router(pyme_router, prefix="/demo")
