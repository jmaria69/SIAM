import datetime as dt

from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String
from .database import Base

class Ticket(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True, index=True)
    ticket_id = Column(String, unique=True, index=True)
    status = Column(String)
    service = Column(String)
    description = Column(String, nullable=True)
    priority = Column(String, nullable=True)


# ---------------------------------------------------------------------------
# Entidades del SOC. Antes vivían solo en memoria (siem/store.py); ahora se
# persisten en el mismo siem.db que ya usaban los tickets — un único motor
# SQLite, no dos sistemas de persistencia distintos. Los campos que en
# siem/models.py son listas (affected_assets, timeline, ttps...) se guardan
# como JSON: para el volumen de una pyme no hace falta normalizar eso en
# tablas propias, y evita una migración de esquema más compleja de la que
# el MVP necesita.
# ---------------------------------------------------------------------------

class AssetDB(Base):
    __tablename__ = "assets"
    id = Column(String, primary_key=True)
    name = Column(String, index=True)
    type = Column(String)
    environment = Column(String, default="produccion")
    criticality = Column(String, default="media")
    owner = Column(String, nullable=True)
    authorized = Column(Boolean, default=True)


class EventDB(Base):
    __tablename__ = "events"
    id = Column(String, primary_key=True)
    source = Column(String)
    external_id = Column(String, nullable=True)
    asset_id = Column(String, nullable=True, index=True)
    asset_name = Column(String, nullable=True)
    event_type = Column(String, default="generico")
    severity = Column(String, default="info", index=True)
    summary = Column(String)
    description = Column(String, nullable=True)
    raw_payload = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=dt.datetime.utcnow, index=True)
    incident_id = Column(String, nullable=True, index=True)
    threat_ids = Column(JSON, default=list)  # ids de siem/threats_catalog.py detectados en este evento


class IncidentDB(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True)
    title = Column(String)
    severity = Column(String, default="media")
    status = Column(String, default="abierto", index=True)
    description = Column(String, default="")
    affected_assets = Column(JSON, default=list)
    event_ids = Column(JSON, default=list)
    timeline = Column(JSON, default=list)
    evidence = Column(JSON, default=list)
    recommendations = Column(JSON, default=list)
    risk_score = Column(Integer, default=0)
    created_at = Column(DateTime, default=dt.datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)
    threat_ids = Column(JSON, default=list)  # unión de threat_ids de sus eventos
    resolved_at = Column(DateTime, nullable=True)  # cuándo pasó a resuelto


class IOCDB(Base):
    __tablename__ = "iocs"
    id = Column(String, primary_key=True)
    type = Column(String)
    value = Column(String)
    campaign = Column(String, nullable=True)
    ttps = Column(JSON, default=list)
    confidence = Column(String, default="media")
    cf_rule_id = Column(String, nullable=True)
    action = Column(String, default="BLOCK")


class WhitelistDB(Base):
    __tablename__ = "whitelist_entries"
    id = Column(String, primary_key=True)
    ip = Column(String, index=True)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class AutomationRuleDB(Base):
    __tablename__ = "automation_rules"
    id = Column(String, primary_key=True)
    name = Column(String)
    trigger = Column(String)
    action = Column(String)
    requires_confirmation = Column(Boolean, default=True)
    enabled = Column(Boolean, default=True)


class ReportDB(Base):
    __tablename__ = "reports"
    id = Column(String, primary_key=True)
    type = Column(String)
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    generated_at = Column(DateTime, default=dt.datetime.utcnow)
    content = Column(String)


class DemoLeadDB(Base):
    __tablename__ = "demo_leads"
    id = Column(String, primary_key=True)
    name = Column(String)
    email = Column(String, index=True)
    phone = Column(String)
    company = Column(String, nullable=True)
    message = Column(String, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow, index=True)
    notified = Column(Boolean, default=False)  # si se pudo avisar por email a ALERT_EMAIL_TO


class CampaignDB(Base):
    __tablename__ = "campaigns"
    id = Column(String, primary_key=True)
    name = Column(String)
    topic = Column(String, default="otro")
    content_type = Column(String, default="comunicado")
    status = Column(String, default="borrador", index=True)
    content = Column(String, nullable=True)
    targets = Column(JSON, default=list)  # lista de CampaignTarget serializados
    created_at = Column(DateTime, default=dt.datetime.utcnow, index=True)
    starts_at = Column(DateTime, nullable=True)
    ends_at = Column(DateTime, nullable=True)
