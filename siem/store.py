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
from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import Session

from siem.active_defense import SEVERITY_ORDER, WAF_SOURCES
from siem.database import get_db
from siem.db_models import (
    AggregatorCursorDB,
    AssetDB,
    AttackerProfileDB,
    AutomationRuleDB,
    CampaignDB,
    EventDB,
    IOCDB,
    IncidentDB,
    ReportDB,
    WhitelistDB,
)
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
    WhitelistEntry,
)
from siem.risk import SEVERITY_WEIGHT

_SEVERITY_RANK = {sev.value: idx for idx, sev in enumerate(SEVERITY_ORDER)}
ATTACKER_PROFILES_CURSOR = "attacker_profiles"

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


def _merge_event_into_profile(profile: AttackerProfileDB, event: EventDB) -> None:
    """Reduce un evento WAF más al perfil acumulado de su IP -- nunca relee
    los eventos ya mezclados, así que todo lo que hace falta para
    reconocer patrones (reincidencia, nº de categorías, nº de días
    activos) tiene que quedar guardado aquí, no derivarse después de los
    eventos crudos."""
    payload = event.raw_payload or {}
    profile.country = payload.get("country") or profile.country
    profile.asn = payload.get("asn") or profile.asn
    profile.asn_org = payload.get("asn_org") or profile.asn_org
    profile.event_count = (profile.event_count or 0) + 1

    severity_counts = dict(profile.severity_counts or {})
    severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
    profile.severity_counts = severity_counts
    profile.max_severity = max(severity_counts, key=lambda s: _SEVERITY_RANK.get(s, -1))
    profile.threat_score = min(100, sum(SEVERITY_WEIGHT.get(sev, 5) * n for sev, n in severity_counts.items()))

    category = payload.get("attack_category")
    if category:
        categories = set(profile.attack_categories or [])
        categories.add(category)
        profile.attack_categories = sorted(categories)

    if event.timestamp is not None:
        day = event.timestamp.strftime("%Y-%m-%d")
        days = set(profile.active_days or [])
        days.add(day)
        profile.active_days = sorted(days)

    if profile.first_seen is None or (event.timestamp is not None and event.timestamp < profile.first_seen):
        profile.first_seen = event.timestamp
    if profile.last_seen is None or (event.timestamp is not None and event.timestamp >= profile.last_seen):
        profile.last_seen = event.timestamp
        profile.last_host = payload.get("host")
        profile.last_uri = payload.get("uri")
        profile.last_user_agent = payload.get("user_agent")
        profile.referer_host = payload.get("referer_host")

    profile.updated_at = dt.datetime.utcnow()


def _row_to_attacker_profile(row: AttackerProfileDB) -> dict:
    return {
        "ip": row.ip,
        "country": row.country,
        "asn": row.asn,
        "asn_org": row.asn_org,
        "event_count": row.event_count or 0,
        "attack_categories": row.attack_categories or [],
        "max_severity": row.max_severity or "info",
        "threat_score": row.threat_score or 0,
        "active_days": row.active_days or [],
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "last_host": row.last_host,
        "last_uri": row.last_uri,
        "last_user_agent": row.last_user_agent,
        "referer_host": row.referer_host,
    }


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
    return IOCDB(id=ioc.id, type=ioc.type, value=ioc.value, campaign=ioc.campaign, ttps=ioc.ttps, confidence=ioc.confidence, cf_rule_id=ioc.cf_rule_id, action=ioc.action)


def _row_to_ioc(row: IOCDB) -> IOC:
    return IOC(id=row.id, type=row.type, value=row.value, campaign=row.campaign, ttps=row.ttps or [], confidence=row.confidence, cf_rule_id=row.cf_rule_id, action=row.action or "BLOCK")


def _whitelist_to_row(entry: WhitelistEntry) -> WhitelistDB:
    return WhitelistDB(id=entry.id, ip=entry.ip, reason=entry.reason, created_at=entry.created_at)


def _row_to_whitelist(row: WhitelistDB) -> WhitelistEntry:
    return WhitelistEntry(id=row.id, ip=row.ip, reason=row.reason, created_at=row.created_at)


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
        # external_id (rayId CF / transaction id Coraza, ver waf.py) no tiene
        # UNIQUE en la tabla -- el pull de Cloudflare cabalga ventanas de
        # lookback solapadas a proposito (10 min de ventana con tick cada
        # 5 min, ver config.py) y sin este check reinserta el mismo evento
        # en cada tick solapado. Simulador/monitoring nunca fijan
        # external_id, asi que no les afecta.
        if event.external_id is not None:
            existing = (
                self.db.query(EventDB)
                .filter(EventDB.external_id == event.external_id)
                .first()
            )
            if existing is not None:
                return _row_to_event(existing)
        self.db.add(_event_to_row(event))
        self.db.commit()
        return event

    def list_events(self, limit: int = 200) -> List[Event]:
        rows = self.db.query(EventDB).order_by(EventDB.timestamp.desc()).limit(limit).all()
        return [_row_to_event(r) for r in rows]

    # -- Perfiles de atacante (siem/attacker_aggregator.py) -------------------
    def aggregate_attacker_profiles(self, batch_size: int = 2000) -> int:
        """Procesa hasta `batch_size` eventos WAF nuevos (desde el cursor
        guardado en aggregator_cursor) y actualiza attacker_profiles.
        Devuelve cuántos eventos procesó -- 0 significa "ya está al día".

        Incremental a propósito: nunca vuelve a leer un evento ya agregado,
        así el coste de cada tick es O(eventos nuevos) y no O(eventos
        totales) -- ver docstring de siem/attacker_aggregator.py para el
        porqué (agrupar en memoria en cada petición no escala a miles de
        IPs distintas).
        """
        cursor = self.db.get(AggregatorCursorDB, ATTACKER_PROFILES_CURSOR)
        query = self.db.query(EventDB).filter(EventDB.source.in_(WAF_SOURCES))
        if cursor is not None and cursor.last_event_timestamp is not None:
            query = query.filter(
                or_(
                    EventDB.timestamp > cursor.last_event_timestamp,
                    and_(
                        EventDB.timestamp == cursor.last_event_timestamp,
                        EventDB.id > (cursor.last_event_id or ""),
                    ),
                )
            )
        events = query.order_by(EventDB.timestamp.asc(), EventDB.id.asc()).limit(batch_size).all()
        if not events:
            return 0

        profiles: dict[str, AttackerProfileDB] = {}
        for event in events:
            ip = (event.raw_payload or {}).get("client_ip")
            if not ip:
                continue
            profile = profiles.get(ip) or self.db.get(AttackerProfileDB, ip)
            if profile is None:
                profile = AttackerProfileDB(
                    ip=ip, severity_counts={}, attack_categories=[], active_days=[],
                )
                self.db.add(profile)
            _merge_event_into_profile(profile, event)
            profiles[ip] = profile

        if cursor is None:
            cursor = AggregatorCursorDB(name=ATTACKER_PROFILES_CURSOR)
            self.db.add(cursor)
        cursor.last_event_timestamp = events[-1].timestamp
        cursor.last_event_id = events[-1].id
        self.db.commit()
        return len(events)

    def list_attacker_profiles(self, limit: int = 100) -> List[dict]:
        rows = (
            self.db.query(AttackerProfileDB)
            .order_by(AttackerProfileDB.threat_score.desc())
            .limit(limit)
            .all()
        )
        return [_row_to_attacker_profile(r) for r in rows]

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

    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        row = self.db.get(IOCDB, ioc_id)
        return _row_to_ioc(row) if row else None

    def remove_ioc(self, ioc_id: str) -> bool:
        row = self.db.get(IOCDB, ioc_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

    # -- Whitelist (IPs que Active Defense nunca debe bloquear) --------------------
    def add_whitelist_entry(self, entry: WhitelistEntry) -> WhitelistEntry:
        self.db.add(_whitelist_to_row(entry))
        self.db.commit()
        return entry

    def list_whitelist(self) -> List[WhitelistEntry]:
        return [_row_to_whitelist(r) for r in self.db.query(WhitelistDB).all()]

    def remove_whitelist_entry(self, entry_id: str) -> bool:
        row = self.db.get(WhitelistDB, entry_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

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
