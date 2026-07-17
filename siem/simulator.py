"""Motor de ejecución del simulador de crisis.

Dispara los pasos de un `Scenario` con delays reales (`asyncio.sleep`)
contra el mismo pipeline de correlación/persistencia que usa el tráfico
real -- ver `_inject_step`, que es exactamente `correlate_event` +
`store.add_event`, igual que `POST /v1/monitoring/ingest`. No existe un
motor "de mentira" aparte.

El registro de ejecuciones (`_runs`) es deliberadamente efímero -- vive en
memoria del proceso, no en siem.db. Es solo metadata de progreso de la
sesión de práctica (para que el dashboard pueda hacer polling), no una
entidad del SOC. Si el servidor se reinicia a mitad de un escenario se
pierde el seguimiento de ESE progreso, pero no los eventos/incidentes ya
inyectados: esos ya están en SQLite como cualquier otro evento real.
"""
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional

from siem.correlation import correlate_event
from siem.database import SessionLocal
from siem.models import Event
from siem.scenarios import Scenario, ScenarioStep, get_scenario
from siem.store import SiemStore

logger = logging.getLogger("siem.simulator")

_runs: dict[str, dict] = {}


def get_run(run_id: str) -> Optional[dict]:
    return _runs.get(run_id)


def _public_run(run: dict) -> dict:
    """Copia del run sin las claves internas (la Task de asyncio no es serializable)."""
    return {k: v for k, v in run.items() if not k.startswith("_")}


def _build_event(step: ScenarioStep, run_id: str) -> Event:
    return Event(
        source=step.source,
        asset_name=step.asset_name,
        event_type=step.event_type,
        severity=step.severity,
        summary=step.summary,
        description=step.description,
        raw_payload={"simulado": True, "run_id": run_id},
    )


def _inject_step(store: SiemStore, run: dict, step: ScenarioStep) -> Event:
    """Inyecta un solo paso: resuelve/crea el activo, corre la correlación
    existente y persiste el evento. Aislado en su propia función (sin
    asyncio.sleep) para poder testearlo de forma síncrona y determinista,
    sin depender de los delays reales del escenario."""
    event = _build_event(step, run["run_id"])
    if event.asset_name and not event.asset_id:
        asset = store.get_or_create_asset_by_name(event.asset_name)
        if asset:
            event.asset_id = asset.id
    correlate_event(store, event)
    store.add_event(event)
    run["completed_steps"] += 1
    run["log"].append(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "event_id": event.id,
            "incident_id": event.incident_id,
            "summary": event.summary,
            "severity": event.severity.value,
            "asset_name": event.asset_name,
        }
    )
    return event


async def _execute(run_id: str, scenario: Scenario) -> None:
    run = _runs[run_id]
    # Sesión propia, independiente de cualquier request: este task sigue
    # vivo mucho después de que la petición HTTP que lo lanzó ya respondió.
    db = SessionLocal()
    store = SiemStore(db)
    try:
        for step in scenario.steps:
            if step.delay_seconds > 0:
                await asyncio.sleep(step.delay_seconds)
            _inject_step(store, run, step)
        run["status"] = "completado"
    except Exception as exc:  # el simulador nunca debe tumbar el proceso principal
        logger.exception("Fallo ejecutando el escenario %s (run %s)", scenario.id, run_id)
        run["status"] = "error"
        run["log"].append({"timestamp": datetime.utcnow().isoformat(), "error": str(exc)})
    finally:
        run["finished_at"] = datetime.utcnow().isoformat()
        db.close()


def start_run(scenario_id: str) -> Optional[dict]:
    """Crea el registro de ejecución y programa la tarea async. Devuelve
    None si el escenario no existe (el router lo traduce a 404)."""
    scenario = get_scenario(scenario_id)
    if not scenario:
        return None
    run_id = f"SIM-{uuid.uuid4().hex[:8]}"
    run = {
        "run_id": run_id,
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "status": "en_curso",
        "total_steps": len(scenario.steps),
        "completed_steps": 0,
        "log": [],
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
    }
    _runs[run_id] = run
    # Se guarda la referencia a la task en el propio run (con clave "_")
    # para que no la recoja el garbage collector antes de terminar -- es un
    # gotcha real y conocido de asyncio.create_task.
    run["_task"] = asyncio.create_task(_execute(run_id, scenario))
    return _public_run(run)


def get_run_public(run_id: str) -> Optional[dict]:
    run = get_run(run_id)
    return _public_run(run) if run else None
