"""Store del SOC (Asset, Event, Incident, IOC, AutomationRule, Report),
respaldado por SQLAlchemy sobre el mismo `siem.db` que ya usaban los
tickets. Sustituye al store en memoria que había antes — José pidió
persistencia real para no perder el historial de simulacros/eventos en
cada reinicio.

Mantiene la misma interfaz pública que el store en memoria (add_asset,
list_incidents, etc.) a propósito: los routers (`siem/router/*.py`) y
`siem/correlation.py` no tuvieron que cambiar su lógica, solo el type hint.
Eso es lo que compró tener un patrón repositorio desde el principio.
"""
from __future__ import annotations

import datetime as dt
from typing import List, Optional

from fastapi import Depends
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from siem.database import get_db
from siem.db_models import AssetDB, AutomationRuleDB, CampaignDB, EventDB, IOCDB, IncidentDB, ReportDB
from siem.models import (
    Asset,
    AutomationRule,
    Campaign,
    CampaignStatus,
    CampaignTarget,
    Event,
    IOC,
    Incident,
    Report,
    TimelineEntry,
)

GRANULARITY_FORMAT = {
    "hour": "%Y-%m-%d %H:00",
    "day": "%Y-%m-%d",
    "month": "%Y-%m",
    "year": "%Y",
}


# ---------------------------------------------------------------------------
# Conversión ORM <-> Pydantic. Los campos DateTime se guardan como objetos
# datetime reales (no strings) porque el tipo DateTime de SQLAlchemy para
# SQLite espera eso al leer/escribir. Los campos JSON (listas, dicts
# anidados como el timeline) sí se serializan a estructuras JSON-safe con
# pydantic (`model_dump(mode="json")`), que Ollama... digo, que SQLite
# guarda tal cual como texto JSON.
# ---------------------------------------------------------------------------

def _asset_to_row(asset: Asset) -> AssetDB:
    return AssetDB(
        id=asset.id, name=asset.name, type=asset.type, environment=asset.environment,
        criticality=asset.criticality.value, owner=asset.owner, authorized=asset.authorized,
    )


def _row_to_asset(row: AssetDB) -> Asset:
    return Asset(
        id=row.id, name=row.name, type=row.type, environment=row.environment,
        criticality=row.criticality, owner=row.owner, authorized=row.authorized,
    )


def _event_to_row(event: Event) -> EventDB:
    return EventDB(
        id=event.id, source=event.source, external_id=event.external_id,
        asset_id=event.asset_id, asset_name=event.asset_name, event_type=event.event_type,
        severity=event.severity.value, summary=event.summary, description=event.description,
        raw_payload=event.raw_payload, timestamp=event.timestamp, incident_id=event.incident_id,
        threat_ids=event.threat_ids,
    )


def _row_to_event(row: EventDB) -> Event:
    return Event(
        id=row.id, source=row.source, external_id=row.external_id,
        asset_id=row.asset_id, asset_name=row.asset_name, event_type=row.event_type,
        severity=row.severity, summary=row.summary, description=row.description,
        raw_payload=row.raw_payload or {}, timestamp=row.timestamp, incident_id=row.incident_id,
        threat_ids=row.threat_ids or [],
    )


def _incident_fields(incident: Incident) -> dict:
    return {
        "title": incident.title,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "description": incident.description,
        "affected_assets": incident.affected_assets,
        "event_ids": incident.event_ids,
        "timeline": [t.model_dump(mode="json") for t in incident.timeline],
        "evidence": incident.evidence,
        "recommendations": incident.recommendations,
        "risk_score": incident.risk_score,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "threat_ids": incident.threat_ids,
        "resolved_at": incident.resolved_at,
    }


def _row_to_incident(row: IncidentDB) -> Incident:
    return Incident(
        id=row.id,
        title=row.title,
        severity=row.severity,
        status=row.status,
        description=row.description or "",
        affected_assets=row.affected_assets or [],
        event_ids=row.event_ids or [],
        timeline=[TimelineEntry(**t) for t in (row.timeline or [])],
        evidence=row.evidence or [],
        recommendations=row.recommendations or [],
        risk_score=row.risk_score or 0,
        created_at=row.created_at,
        updated_at=row.updated_at,
        threat_ids=row.threat_ids or [],
        resolved_at=row.resolved_at,
    )


def _ioc_to_row(ioc: IOC) -> IOCDB:
    return IOCDB(id=ioc.id, type=ioc.type, value=ioc.value, campaign=ioc.campaign, ttps=ioc.ttps, confidence=ioc.confidence)


def _row_to_ioc(row: IOCDB) -> IOC:
    return IOC(id=row.id, type=row.type, value=row.value, campaign=row.campaign, ttps=row.ttps or [], confidence=row.confidence)


def _rule_to_row(rule: AutomationRule) -> AutomationRuleDB:
    return AutomationRuleDB(
        id=rule.id, name=rule.name, trigger=rule.trigger, action=rule.action.value,
        requires_confirmation=rule.requires_confirmation, enabled=rule.enabled,
    )


def _row_to_rule(row: AutomationRuleDB) -> AutomationRule:
    return AutomationRule(
        id=row.id, name=row.name, trigger=row.trigger, action=row.action,
        requires_confirmation=row.requires_confirmation, enabled=row.enabled,
    )


def _report_to_row(report: Report) -> ReportDB:
    return ReportDB(
        id=report.id, type=report.type.value, period_start=report.period_start,
        period_end=report.period_end, generated_at=report.generated_at, content=report.content,
    )


def _row_to_report(row: ReportDB) -> Report:
    return Report(
        id=row.id, type=row.type, period_start=row.period_start,
        period_end=row.period_end, generated_at=row.generated_at, content=row.content,
    )


def _campaign_fields(campaign: Campaign) -> dict:
    return {
        "name": campaign.name,
        "topic": campaign.topic.value,
        "content_type": campaign.content_type.value,
        "status": campaign.status.value,
        "content": campaign.content,
        "targets": [t.model_dump(mode="json") for t in campaign.targets],
        "created_at": campaign.created_at,
        "starts_at": campaign.starts_at,
        "ends_at": campaign.ends_at,
    }


def _row_to_campaign(row: CampaignDB) -> Campaign:
    return Campaign(
        id=row.id,
        name=row.name,
        topic=row.topic,
        content_type=row.content_type,
        status=row.status,
        content=row.content,
        targets=[CampaignTarget(**t) for t in (row.targets or [])],
        created_at=row.created_at,
        starts_at=row.starts_at,
        ends_at=row.ends_at,
    )


class SiemStore:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -- Assets ------------------------------------------------------------
    def add_asset(self, asset: Asset) -> Asset:
        self.db.add(_asset_to_row(asset))
        self.db.commit()
        return asset

    def list_assets(self) -> List[Asset]:
        return [_row_to_asset(r) for r in self.db.query(AssetDB).all()]

    def get_or_create_asset_by_name(self, name: Optional[str]) -> Optional[Asset]:
        if not name:
            return None
        row = self.db.query(AssetDB).filter(AssetDB.name == name).first()
        if row:
            return _row_to_asset(row)
        return self.add_asset(Asset(name=name, type="desconocido"))

    # -- Events --------------------------------------------------------------
    def add_event(self, event: Event) -> Event:
        self.db.add(_event_to_row(event))
        self.db.commit()
        return event

    def list_events(self, limit: int = 200) -> List[Event]:
        rows = self.db.query(EventDB).order_by(EventDB.timestamp.desc()).limit(limit).all()
        return [_row_to_event(r) for r in rows]

    # -- Incidents -----------------------------------------------------------
    def add_incident(self, incident: Incident) -> Incident:
        row = IncidentDB(id=incident.id, **_incident_fields(incident))
        self.db.add(row)
        self.db.commit()
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        row = self.db.get(IncidentDB, incident_id)
        return _row_to_incident(row) if row else None

    def list_incidents(self) -> List[Incident]:
        rows = self.db.query(IncidentDB).order_by(IncidentDB.created_at.desc()).all()
        return [_row_to_incident(r) for r in rows]

    def update_incident(self, incident: Incident) -> Incident:
        row = self.db.get(IncidentDB, incident.id)
        if row is None:
            return self.add_incident(incident)
        for key, value in _incident_fields(incident).items():
            setattr(row, key, value)
        self.db.commit()
        return incident

    def delete_incident(self, incident_id: str) -> bool:
        row = self.db.get(IncidentDB, incident_id)
        if row is None:
            return False
        # Los eventos correlacionados se desvinculan (incident_id=None) en vez
        # de borrarse: siguen siendo telemetría/evidencia histórica válida
        # aunque el incidente que los agrupaba ya no exista.
        self.db.query(EventDB).filter(EventDB.incident_id == incident_id).update(
            {"incident_id": None}
        )
        self.db.delete(row)
        self.db.commit()
        return True

    # -- IOCs ------------------------------------------------------------------
    def add_ioc(self, ioc: IOC) -> IOC:
        self.db.add(_ioc_to_row(ioc))
        self.db.commit()
        return ioc

    def list_iocs(self) -> List[IOC]:
        return [_row_to_ioc(r) for r in self.db.query(IOCDB).all()]

    # -- Automation rules --------------------------------------------------------
    def add_rule(self, rule: AutomationRule) -> AutomationRule:
        self.db.add(_rule_to_row(rule))
        self.db.commit()
        return rule

    def list_rules(self) -> List[AutomationRule]:
        return [_row_to_rule(r) for r in self.db.query(AutomationRuleDB).all()]

    def get_rule(self, rule_id: str) -> Optional[AutomationRule]:
        row = self.db.get(AutomationRuleDB, rule_id)
        return _row_to_rule(row) if row else None

    # -- Reports -------------------------------------------------------------------
    def add_report(self, report: Report) -> Report:
        self.db.add(_report_to_row(report))
        self.db.commit()
        return report

    def list_reports(self) -> List[Report]:
        rows = self.db.query(ReportDB).order_by(ReportDB.generated_at.desc()).all()
        return [_row_to_report(r) for r in rows]

    # -- Métricas por tiempo (módulo 1: "ataques en tiempo real, hora, día, mes, año") --
    def timeseries(self, granularity: str, limit: int = 30) -> List[dict]:
        fmt = GRANULARITY_FORMAT.get(granularity, GRANULARITY_FORMAT["day"])
        bucket = func.strftime(fmt, EventDB.timestamp)
        rows = (
            self.db.query(
                bucket.label("periodo"),
                func.count(EventDB.id).label("eventos"),
                func.sum(case((EventDB.severity == "critica", 1), else_=0)).label("criticos"),
            )
            .group_by(bucket)
            .order_by(bucket.desc())
            .limit(limit)
            .all()
        )
        return [
            {"periodo": r.periodo, "eventos": r.eventos, "criticos": int(r.criticos or 0)}
            for r in reversed(rows)
        ]

    def eventos_ultimo_minuto(self) -> int:
        cutoff = dt.datetime.utcnow() - dt.timedelta(minutes=1)
        return self.db.query(EventDB).filter(EventDB.timestamp >= cutoff).count()

    # -- Campañas de concienciación -------------------------------------------------
    def add_campaign(self, campaign: Campaign) -> Campaign:
        row = CampaignDB(id=campaign.id, **_campaign_fields(campaign))
        self.db.add(row)
        self.db.commit()
        return campaign

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        row = self.db.get(CampaignDB, campaign_id)
        return _row_to_campaign(row) if row else None

    def list_campaigns(self) -> List[Campaign]:
        rows = self.db.query(CampaignDB).order_by(CampaignDB.created_at.desc()).all()
        return [_row_to_campaign(r) for r in rows]

    def update_campaign(self, campaign: Campaign) -> Campaign:
        row = self.db.get(CampaignDB, campaign.id)
        if row is None:
            return self.add_campaign(campaign)
        for key, value in _campaign_fields(campaign).items():
            setattr(row, key, value)
        self.db.commit()
        return campaign

    def delete_campaign(self, campaign_id: str) -> bool:
        row = self.db.get(CampaignDB, campaign_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

    def list_due_campaigns(self) -> List[Campaign]:
        """Campañas con `starts_at` vencido, todavía en borrador y con
        contenido ya generado -- usado por `siem/campaign_scheduler.py`
        para el envío automático. Deliberadamente NO envía campañas sin
        contenido: generar el contenido con IA sigue siendo una acción
        humana explícita ("Generar contenido con IA"), no algo que se
        dispare solo a una hora concreta sin que nadie lo haya revisado
        antes de que salga hacia empleados reales."""
        now = dt.datetime.utcnow()
        rows = (
            self.db.query(CampaignDB)
            .filter(
                CampaignDB.status == CampaignStatus.BORRADOR.value,
                CampaignDB.starts_at.isnot(None),
                CampaignDB.starts_at <= now,
                CampaignDB.content.isnot(None),
            )
            .all()
        )
        return [_row_to_campaign(r) for r in rows]


def get_store(db: Session = Depends(get_db)) -> SiemStore:
    """Dependency de FastAPI — una sesión de base de datos por request,
    igual que ya hacía `siem.database.get_db` para los tickets."""
    return SiemStore(db)
