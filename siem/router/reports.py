"""Informes (módulo 7) y panel ejecutivo (módulo 8)."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends

from siem.ai import get_ai_provider
from siem.config import Settings, get_settings
from siem.models import IncidentStatus, Report, ReportType
from siem.risk import calculate_global_risk
from siem.store import SiemStore, get_store

router = APIRouter(prefix="/v1/reports", tags=["informes"])

PERIOD_DELTA = {
    ReportType.DAILY: timedelta(days=1),
    ReportType.WEEKLY: timedelta(weeks=1),
    ReportType.MONTHLY: timedelta(days=30),
}


def _build_report(
    report_type: ReportType, store: SiemStore, settings: Settings
) -> Report:
    period_end = datetime.utcnow()
    period_start = period_end - PERIOD_DELTA[report_type]

    incidents = [i for i in store.list_incidents() if i.created_at >= period_start]
    resolved = [i for i in incidents if i.status == IncidentStatus.RESUELTO]

    data_points = [
        f"Incidentes nuevos: {len(incidents)}",
        f"Incidentes resueltos: {len(resolved)}",
        f"Riesgo global actual: {calculate_global_risk(store.list_incidents())}/100",
    ] + [f"{i.id}: {i.title} (severidad {i.severity.value}, estado {i.status.value})" for i in incidents[:10]]

    provider = get_ai_provider(settings)
    content = provider.summarize(f"Informe {report_type.value} — SIEM Security", data_points)

    report = Report(type=report_type, period_start=period_start, period_end=period_end, content=content)
    store.add_report(report)
    return report


@router.get("/daily", response_model=Report)
def daily_report(store: SiemStore = Depends(get_store), settings: Settings = Depends(get_settings)) -> Report:
    return _build_report(ReportType.DAILY, store, settings)


@router.get("/weekly", response_model=Report)
def weekly_report(store: SiemStore = Depends(get_store), settings: Settings = Depends(get_settings)) -> Report:
    return _build_report(ReportType.WEEKLY, store, settings)


@router.get("/monthly", response_model=Report)
def monthly_report(store: SiemStore = Depends(get_store), settings: Settings = Depends(get_settings)) -> Report:
    return _build_report(ReportType.MONTHLY, store, settings)


@router.get("/executive")
def executive_panel(store: SiemStore = Depends(get_store)) -> dict:
    """Módulo 8: resumen no técnico orientado a gerencia."""
    incidents = store.list_incidents()
    open_incidents = [i for i in incidents if i.status != IncidentStatus.RESUELTO]
    critical_open = [i for i in open_incidents if i.severity.value == "critica"]

    return {
        "nivel_riesgo": calculate_global_risk(incidents),
        "incidentes_abiertos": len(open_incidents),
        "incidentes_criticos_abiertos": len(critical_open),
        "incidentes_resueltos_total": len(incidents) - len(open_incidents),
        "principales_amenazas": [
            {"titulo": i.title, "severidad": i.severity.value} for i in critical_open[:5]
        ],
        "resumen": (
            "Sin incidentes críticos abiertos. Postura de seguridad estable."
            if not critical_open
            else f"{len(critical_open)} incidente(s) crítico(s) requieren atención inmediata."
        ),
    }
