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


class AttackerProfileDB(Base):
    """Resumen incremental por IP atacante, mantenido por
    siem/attacker_aggregator.py -- ver su docstring para el porqué (evitar
    reagrupar todos los eventos WAF en memoria en cada petición a
    /v1/active-defense/overview cuando hay miles de IPs distintas).

    severity_counts/attack_categories/active_days se guardan ya reducidos
    (conteos/sets, no la lista de eventos crudos) para que el perfil quepa
    en una fila sin importar cuántos eventos WAF haya detrás. threat_score
    se recalcula en cada evento nuevo con la misma fórmula que
    active_defense.compute_threat_score, así ORDER BY threat_score en SQL
    da el mismo orden que antes se calculaba en Python.
    """
    __tablename__ = "attacker_profiles"
    ip = Column(String, primary_key=True)
    country = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    asn_org = Column(String, nullable=True)
    event_count = Column(Integer, default=0)
    severity_counts = Column(JSON, default=dict)  # {"critica": 2, "alta": 5, ...}
    max_severity = Column(String, default="info")
    attack_categories = Column(JSON, default=list)
    active_days = Column(JSON, default=list)  # "YYYY-MM-DD" distintos con actividad -- señal de persistencia
    threat_score = Column(Integer, default=0, index=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    last_host = Column(String, nullable=True)
    last_uri = Column(String, nullable=True)
    last_user_agent = Column(String, nullable=True)
    referer_host = Column(String, nullable=True)
    updated_at = Column(DateTime, default=dt.datetime.utcnow)
    # Enriquecimiento WHOIS/RDAP (siem/ip_intel.py), rellenado una sola vez
    # por IP cuando se convierte en reincidente confirmado -- ver
    # siem/attacker_aggregator.py::apply_auto_responses. intel_fetched_at
    # NULL = todavía no se ha intentado (no "se intentó y no había datos");
    # así no se reintenta en cada tick del agregador.
    whois_org = Column(String, nullable=True)
    whois_network_name = Column(String, nullable=True)
    whois_abuse_email = Column(String, nullable=True)
    intel_fetched_at = Column(DateTime, nullable=True)


class AggregatorCursorDB(Base):
    """Punto por donde se quedó cada agregador incremental (una fila por
    `name`). Vive en base de datos, no en memoria del proceso, por el mismo
    motivo que ya documentó campaign_scheduler.py sobre starts_at: si el
    servidor se reinicia, el siguiente tick retoma justo donde lo dejó en
    vez de perder el progreso o reprocesar todo desde cero."""
    __tablename__ = "aggregator_cursor"
    name = Column(String, primary_key=True)
    last_event_timestamp = Column(DateTime, nullable=True)
    last_event_id = Column(String, nullable=True)


class RuntimeSettingDB(Base):
    """Overrides en caliente de flags que por defecto viven en .env
    (siem/config.py::Settings) -- una fila por `key`. Solo hace falta para
    los que un analista debe poder cambiar desde el dashboard sin acceso al
    servidor (hoy: auto_honeypot_repeat_offenders, ver
    siem/router/active_defense.py). Ausencia de fila = sin override, se usa
    el valor de .env; mismo criterio que AggregatorCursorDB para no acoplar
    esto a memoria del proceso."""
    __tablename__ = "runtime_settings"
    key = Column(String, primary_key=True)
    value_bool = Column(Boolean, nullable=True)


class EvidenceDB(Base):
    """Expediente de Defensa: registro append-only de hechos probatorios,
    encadenado por hash (ver siem/evidence.py).

    Por qué existe: SIAM ya GENERABA toda la evidencia que pide un auditor
    NIS2 o el cuestionario de una aseguradora (bloqueos reales, sesiones de
    señuelo, simulacros de phishing, incidentes contenidos, PDS/BIA
    generados) y la tiraba a la basura -- los módulos PYME son calculadoras
    de un solo uso y los informes se construyen al vuelo. Sin un registro
    fechado no se puede DEMOSTRAR nada a posteriori, que es exactamente
    donde una pyme suspende el cuestionario.

    `prev_hash`/`hash` encadenan cada fila con la anterior: retocar una fila
    vieja para "mejorar" el expediente rompe la cadena a partir de ahí y
    GET /v1/evidence/verify lo delata. Es evidencia a prueba de
    manipulación, no criptografía fuerte -- quien controle el servidor puede
    recalcular la cadena entera; lo que se impide es el retoque silencioso
    de una fila suelta.

    `seq` (autoincrement) da el orden de la cadena pero NO entra en el hash:
    lo asigna SQLite en el INSERT y tendría que conocerse antes de calcular
    el hash. El enlace real lo da prev_hash, que ya fija el orden de forma
    unívoca.
    """
    __tablename__ = "evidence_ledger"
    seq = Column(Integer, primary_key=True, autoincrement=True)
    id = Column(String, unique=True, index=True)  # EVD-xxxxxxxx
    recorded_at = Column(DateTime, default=dt.datetime.utcnow, index=True)
    kind = Column(String, index=True)  # ver siem/models.py::EvidenceKind
    # Controles del checklist de auditoría (siem/course_cybersecurity.py::
    # get_audit_checklist, ids c1..c15) + los propios de SIAM (s1..s3, ver
    # siem/evidence.py::CONTROLS) que esta evidencia respalda.
    control_ids = Column(JSON, default=list)
    title = Column(String)
    summary = Column(String)
    payload = Column(JSON, default=dict)  # detalle estructurado del hecho
    source_ref = Column(String, nullable=True)  # INC-xxx, CAMP-xxx, una IP...
    actor = Column(String, default="sistema")  # "sistema", "IA", usuario
    prev_hash = Column(String, nullable=True)  # NULL solo en la fila génesis
    hash = Column(String, index=True)


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
