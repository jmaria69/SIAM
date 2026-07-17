"""Cálculo de riesgo global 0-100 para el Centro de Monitorización (módulo 1).

Fórmula deliberadamente simple y explicable para el MVP: pondera incidentes
abiertos por severidad. Nada de modelos de ML aquí todavía — un score que
nadie puede explicar en una demo a un gerente de pyme es peor que uno simple
y defendible.
"""
from siem.models import Incident, IncidentStatus, Severity

SEVERITY_WEIGHT = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 18,
    Severity.CRITICAL: 30,
}


def calculate_global_risk(incidents: list[Incident]) -> int:
    """Devuelve un score 0-100. Satura en 100 para no dar falsa sensación de
    precisión más allá de ese punto (a partir de cierto número de incidentes
    críticos abiertos, la pyme ya está en crisis; el número exacto deja de
    importar)."""
    open_incidents = [i for i in incidents if i.status != IncidentStatus.RESUELTO]
    if not open_incidents:
        return 0
    raw = sum(SEVERITY_WEIGHT.get(i.severity, 5) for i in open_incidents)
    return min(100, raw)


def calculate_incident_risk(incident: Incident, affected_asset_count: int) -> int:
    """Score de riesgo por incidente individual, usado al crear/actualizar uno."""
    base = SEVERITY_WEIGHT.get(incident.severity, 5) * 3
    asset_factor = min(affected_asset_count, 5) * 4
    return min(100, base + asset_factor)
