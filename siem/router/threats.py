"""Catálogo de amenazas + qué se ha detectado de verdad (2026-07-05).

`GET /v1/threats` expone el catálogo estático de 30 amenazas
(siem/threats_catalog.py). `GET /v1/threats/detectados` cruza ese catálogo
con los incidentes reales del store para responder "¿cuáles de estas 30
amenazas hemos visto de verdad, y en qué incidentes" -- sin este cruce, el
catálogo sería solo un PDF más dentro de la app. `GET /v1/threats/{id}`
devuelve una amenaza concreta.

`/detectados` se registra ANTES que `/{threat_id}` a propósito: mismo
motivo que `/v1/campaigns/analytics` en siem/router/campaigns.py -- si
fuera al revés, `/v1/threats/detectados` coincidiría con el patrón de un
único segmento `/{threat_id}` y, aunque threat_id está tipado como int
(FastAPI ya devolvería 404/422 al no poder convertir "detectados" a int),
se deja en este orden por claridad y por si threat_id dejara de ser int en
el futuro.
"""
from fastapi import APIRouter, Depends, HTTPException

from siem.store import SiemStore, get_store
from siem.threats_catalog import THREATS_CATALOG, get_threat

router = APIRouter(prefix="/v1/threats", tags=["amenazas"])


@router.get("")
def list_threats() -> list[dict]:
    return THREATS_CATALOG


@router.get("/detectados")
def list_detected_threats(store: SiemStore = Depends(get_store)) -> list[dict]:
    """Para cada amenaza del catálogo que aparece en `threat_ids` de al
    menos un incidente real, devuelve la amenaza junto con los incidentes
    donde se detectó. Las amenazas nunca detectadas no aparecen aquí (para
    verlas todas, usa `GET /v1/threats`)."""
    incidents = store.list_incidents()

    incidents_by_threat: dict[int, list[dict]] = {}
    for incident in incidents:
        for threat_id in incident.threat_ids:
            incidents_by_threat.setdefault(threat_id, []).append(
                {
                    "incident_id": incident.id,
                    "title": incident.title,
                    "severity": incident.severity.value,
                    "status": incident.status.value,
                    "created_at": incident.created_at.isoformat(),
                }
            )

    return [
        {**threat, "incidentes_detectados": incidents_by_threat[threat["id"]]}
        for threat in THREATS_CATALOG
        if threat["id"] in incidents_by_threat
    ]


@router.get("/{threat_id}")
def get_threat_entry(threat_id: int) -> dict:
    threat = get_threat(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Amenaza no encontrada")
    return threat
