"""Centro de monitorización (módulo 1) + ingesta genérica de eventos.

`POST /v1/monitoring/ingest` es el punto de entrada para orígenes que no son
Jira (EDR, firewall, logs de cloud...) — el ingest de Jira existente
(`siem/router/api.py`, `/v1/ingest/jira`) sigue funcionando igual y queda
intacto; este es un camino nuevo y paralelo para eventos ya normalizados.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from siem.correlation import correlate_event
from siem.models import Asset, Event, IncidentStatus
from siem.risk import calculate_global_risk
from siem.scenarios import list_scenarios
from siem.simulator import get_run_public, start_run
from siem.store import SiemStore, get_store

router = APIRouter(prefix="/v1/monitoring", tags=["monitorizacion"])

VALID_GRANULARITIES = {"hour", "day", "month", "year"}


@router.post("/ingest", response_model=Event)
def ingest_event(event: Event, store: SiemStore = Depends(get_store)) -> Event:
    """Ingesta un evento ya normalizado y dispara la correlación (módulo 4)."""
    if event.asset_name and not event.asset_id:
        asset: Asset | None = store.get_or_create_asset_by_name(event.asset_name)
        if asset:
            event.asset_id = asset.id
    # Correlacionar ANTES de persistir el evento: así el `incident_id` que
    # correlate_event le asigna al objeto en memoria ya viaja en la fila que
    # se escribe. Al revés (como estaba antes, pensado para el store en
    # memoria) el evento se guardaba con incident_id=None para siempre,
    # porque mutar el objeto después de escribirlo no actualiza la fila.
    correlate_event(store, event)
    store.add_event(event)
    return event


@router.get("/overview")
def get_overview(store: SiemStore = Depends(get_store)) -> dict:
    incidents = store.list_incidents()
    open_incidents = [i for i in incidents if i.status != IncidentStatus.RESUELTO]
    events = store.list_events()

    return {
        "riesgo_global": calculate_global_risk(incidents),
        "activos_monitorizados": len(store.list_assets()),
        "eventos_recientes": [e.model_dump() for e in events[:10]],
        "alertas_abiertas": len(open_incidents),
        "eventos_ultimo_minuto": store.eventos_ultimo_minuto(),
        "incidentes_por_severidad": {
            sev.value: len([i for i in open_incidents if i.severity == sev])
            for sev in {i.severity for i in open_incidents}
        },
        "kpis": {
            "total_incidentes": len(incidents),
            "incidentes_resueltos": len(incidents) - len(open_incidents),
            "eventos_totales": len(events),
            "tiempo_generacion": datetime.utcnow().isoformat(),
        },
    }


@router.get("/timeseries")
def get_timeseries(granularity: str = "day", store: SiemStore = Depends(get_store)) -> dict:
    """Módulo 1: ataques a lo largo del tiempo — hora, día, mes o año.
    "Tiempo real" se cubre con `eventos_ultimo_minuto` en /overview, que el
    dashboard ya sondea cada pocos segundos; no hace falta un websocket
    aparte para una vista que se refresca sola."""
    if granularity not in VALID_GRANULARITIES:
        granularity = "day"
    return {"granularity": granularity, "buckets": store.timeseries(granularity)}


@router.get("/assets", response_model=list[Asset])
def list_assets(store: SiemStore = Depends(get_store)) -> list[Asset]:
    return store.list_assets()


@router.post("/assets", response_model=Asset)
def create_asset(asset: Asset, store: SiemStore = Depends(get_store)) -> Asset:
    return store.add_asset(asset)


# ---------------------------------------------------------------------------
# Simulador de crisis: practicar sobre el mismo pipeline que un incidente
# real, con delays reales entre eventos. Ver siem/scenarios.py (biblioteca)
# y siem/simulator.py (motor de ejecución async).
# ---------------------------------------------------------------------------
@router.get("/scenarios")
def get_scenarios() -> list[dict]:
    return [
        {"id": s.id, "name": s.name, "description": s.description, "total_steps": len(s.steps)}
        for s in list_scenarios()
    ]


@router.post("/simulate/{scenario_id}")
async def simulate(scenario_id: str) -> dict:
    """Lanza un escenario en segundo plano (asyncio.create_task, no
    BackgroundTasks): así sigue corriendo aunque la respuesta ya se haya
    enviado, con su propia sesión de base de datos independiente de esta
    request. Devuelve el run_id para que el dashboard haga polling del
    progreso en /simulate/{run_id}/status."""
    run = start_run(scenario_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Escenario no encontrado")
    return run


@router.get("/simulate/{run_id}/status")
def simulate_status(run_id: str) -> dict:
    run = get_run_public(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Ejecución no encontrada")
    return run
