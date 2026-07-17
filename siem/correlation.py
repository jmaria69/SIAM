"""Correlación de eventos (módulo 4).

Estrategia MVP: determinista, no ML. Un evento nuevo se agrupa con un
incidente abierto existente si comparte el mismo activo y cae dentro de la
ventana temporal configurada (`CORRELATION_WINDOW_MINUTES`, por defecto 15
min). Si no hay incidente al que unirse, se crea uno nuevo. Esto ya cumple
el objetivo del prompt de "agrupar eventos relacionados y generar un único
caso cuando varios eventos formen parte del mismo problema" sin necesitar
un motor de reglas complejo que nadie podría auditar en el MVP.
"""
from datetime import timedelta
from typing import Optional

from siem.config import get_settings
from siem.models import Event, Incident, IncidentStatus, Severity, TimelineEntry
from siem.risk import calculate_incident_risk
from siem.store import SiemStore
from siem.threat_detection import detect_threats
from siem.threats_catalog import get_threat

SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


def _recommendation_for_threat(threat_id: int) -> Optional[str]:
    threat = get_threat(threat_id)
    if not threat:
        return None
    return f"Amenaza detectada — {threat['nombre']}: {threat['prevencion']}"


def _append_new_threat_recommendations(incident: Incident, new_threat_ids: list[int]) -> None:
    """Añade la recomendación de prevención del catálogo por cada amenaza
    NUEVA detectada en este incidente -- no se toca si ya estaba (evita
    duplicar el mismo texto en cada evento correlacionado) y no se borra
    nada de lo que ya hubiera en `recommendations` (p.ej. explicaciones de
    `POST /v1/incidents/{id}/explain`, que solo hacen append -- ver
    siem/router/incidents.py). Es la pieza que conecta "qué se detectó" con
    "cómo se resuelve" sin necesidad de que nadie pulse un botón aparte."""
    for threat_id in new_threat_ids:
        recommendation = _recommendation_for_threat(threat_id)
        if recommendation and recommendation not in incident.recommendations:
            incident.recommendations.append(recommendation)


def _asset_ref(event: Event) -> Optional[str]:
    """Referencia única del activo para agrupar y mostrar en `affected_assets`.

    Antes se metían asset_id Y asset_name a la vez cuando ambos estaban
    disponibles (típico si el evento viene con `asset_name` y
    `siem/router/monitoring.py` ya resolvió el `asset_id` correspondiente),
    lo que dejaba entradas duplicadas para el mismo activo, p.ej.
    ['AST-abc123', 'web-prod-01']. Se usa una sola referencia: el nombre
    (más legible en el dashboard) si existe, si no el id.
    """
    return event.asset_name or event.asset_id


def correlate_event(store: SiemStore, event: Event) -> Incident:
    """Asocia el evento a un incidente existente o crea uno nuevo. Devuelve
    el incidente resultante."""
    settings = get_settings()
    window = timedelta(minutes=settings.CORRELATION_WINDOW_MINUTES)

    # Detección de amenazas (2026-07-05, reglas por palabra clave sobre el
    # catálogo de siem/threats_catalog.py) -- se hace aquí, no en cada
    # router/simulador por separado, porque correlate_event es el único
    # camino real por el que pasa cualquier evento (ingesta real y
    # simulador usan exactamente esta función, ver docstring de
    # siem/simulator.py). Un único sitio, no dos implementaciones que
    # puedan divergir -- mismo criterio que send_campaign_now.
    event.threat_ids = detect_threats(event)

    ref = _asset_ref(event)

    candidate = None
    if ref:
        for incident in store.list_incidents():
            if incident.status == IncidentStatus.RESUELTO:
                continue
            if event.timestamp - incident.updated_at > window:
                continue
            if ref in incident.affected_assets:
                candidate = incident
                break

    if candidate is None:
        incident = Incident(
            title=f"Incidente: {event.summary}"[:120],
            severity=event.severity,
            description=event.description or event.summary,
            affected_assets=[ref] if ref else [],
            event_ids=[event.id],
            threat_ids=list(event.threat_ids),
        )
        incident.timeline.append(
            TimelineEntry(actor="sistema", description=f"Incidente creado a partir del evento {event.id}")
        )
        _append_new_threat_recommendations(incident, event.threat_ids)
        incident.risk_score = calculate_incident_risk(incident, len(incident.affected_assets))
        store.add_incident(incident)
        event.incident_id = incident.id
        return incident

    # Se une al incidente existente: agrupa, reduce ruido de falsos positivos
    # duplicados y sube severidad si el nuevo evento es más grave.
    candidate.event_ids.append(event.id)
    candidate.severity = _max_severity(candidate.severity, event.severity)
    if ref and ref not in candidate.affected_assets:
        candidate.affected_assets.append(ref)
    new_threat_ids = [t for t in event.threat_ids if t not in candidate.threat_ids]
    candidate.threat_ids.extend(new_threat_ids)
    _append_new_threat_recommendations(candidate, new_threat_ids)
    candidate.timeline.append(
        TimelineEntry(actor="sistema", description=f"Evento {event.id} correlacionado a este incidente")
    )
    candidate.risk_score = calculate_incident_risk(candidate, len(candidate.affected_assets))
    from datetime import datetime

    candidate.updated_at = datetime.utcnow()
    store.update_incident(candidate)
    event.incident_id = candidate.id
    return candidate
