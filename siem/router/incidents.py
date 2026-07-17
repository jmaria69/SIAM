"""Gestión de incidentes (módulo 3)."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from siem.ai import get_ai_provider
from siem.config import Settings, get_settings
from siem.models import Incident, IncidentStatus, TimelineEntry
from siem.store import SiemStore, get_store

router = APIRouter(prefix="/v1/incidents", tags=["incidentes"])


@router.get("", response_model=list[Incident])
def list_incidents(
    status: Optional[IncidentStatus] = None, store: SiemStore = Depends(get_store)
) -> list[Incident]:
    incidents = store.list_incidents()
    if status:
        incidents = [i for i in incidents if i.status == status]
    return incidents


@router.get("/{incident_id}", response_model=Incident)
def get_incident(incident_id: str, store: SiemStore = Depends(get_store)) -> Incident:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    return incident


class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    description: Optional[str] = None


@router.patch("/{incident_id}", response_model=Incident)
def update_incident(
    incident_id: str, update: IncidentUpdate, store: SiemStore = Depends(get_store)
) -> Incident:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    if update.status:
        incident.timeline.append(
            TimelineEntry(actor="usuario", description=f"Estado cambiado a {update.status.value}")
        )
        # Marca de tiempo de resolución: se fija solo en la transición a
        # resuelto (re-marcar resuelto un incidente ya resuelto no la mueve)
        # y se limpia al reabrir — un incidente reabierto aún no tiene tiempo
        # de resolución válido.
        if update.status == IncidentStatus.RESUELTO:
            if incident.status != IncidentStatus.RESUELTO:
                incident.resolved_at = datetime.utcnow()
        else:
            incident.resolved_at = None
        incident.status = update.status
    if update.description is not None:
        incident.description = update.description
    incident.updated_at = datetime.utcnow()
    return store.update_incident(incident)


@router.delete("/{incident_id}", status_code=204)
def delete_incident(incident_id: str, store: SiemStore = Depends(get_store)) -> None:
    """Elimina definitivamente un incidente, solo si ya está resuelto.

    La restricción es deliberada: un incidente abierto o en investigación es
    trabajo pendiente y borrarlo desde la UI sería destruir el registro de un
    problema sin resolver. Resolver primero, eliminar después.
    """
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    if incident.status != IncidentStatus.RESUELTO:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Solo se pueden eliminar incidentes resueltos "
                f"(estado actual: {incident.status.value}). Márcalo como resuelto primero."
            ),
        )
    store.delete_incident(incident_id)


class IncidentAction(BaseModel):
    actor: str
    description: str


@router.post("/{incident_id}/actions", response_model=Incident)
def log_action(
    incident_id: str, action: IncidentAction, store: SiemStore = Depends(get_store)
) -> Incident:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    incident.timeline.append(TimelineEntry(actor=action.actor, description=action.description))
    incident.updated_at = datetime.utcnow()
    return store.update_incident(incident)


@router.post("/{incident_id}/explain")
def explain_incident(
    incident_id: str,
    store: SiemStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Módulo 2: explica el incidente en lenguaje claro y sugiere mitigación."""
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    provider = get_ai_provider(settings)
    # Bug real (2026-07-16): en producción el contenedor no llegaba al Ollama
    # del host (LOCAL_LLM_URL=127.0.0.1 apunta al propio contenedor) y la
    # APIConnectionError salía como 500 pelado — el dashboard no mostraba
    # nada. get_ai_provider solo protege errores de INICIALIZACIÓN; el fallo
    # en tiempo de llamada hay que capturarlo aquí y devolverlo como un 502
    # con mensaje claro que la UI pueda enseñar.
    try:
        explanation = provider.explain_incident(incident)
    except Exception as exc:  # noqa: BLE001 — cualquier fallo del proveedor es el mismo caso
        raise HTTPException(
            status_code=502,
            detail=(
                f"El proveedor de IA '{provider.name}' no respondió ({type(exc).__name__}). "
                "Revisa AI_PROVIDER y su configuración (API key / LOCAL_LLM_URL) en el servidor."
            ),
        ) from exc
    incident.recommendations.append(explanation)
    store.update_incident(incident)
    return {"incident_id": incident_id, "proveedor_ia": provider.name, "explicacion": explanation}
