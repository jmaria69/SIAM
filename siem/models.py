"""Modelo de datos de SIEM Security (fase MVP).

Se mantiene `SiemTicket` por compatibilidad con la integración de Jira ya
existente, pero el núcleo del SOC gira alrededor de Asset -> Event -> Incident.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Compatibilidad con la integración Jira original
# ---------------------------------------------------------------------------
class SiemTicket(BaseModel):
    ticket_id: str
    status: str
    service: str
    description: Optional[str] = None
    priority: Optional[str] = None


# ---------------------------------------------------------------------------
# Roles (módulo 10)
# ---------------------------------------------------------------------------
class Role(str, Enum):
    SUPERADMIN = "superadmin"
    ADMIN = "admin"
    IT_RESPONSABLE = "it_responsable"
    ANALISTA = "analista"
    AUDITOR = "auditor"
    DIRECCION = "direccion"


# ---------------------------------------------------------------------------
# Activos
# ---------------------------------------------------------------------------
class AssetCriticality(str, Enum):
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"
    CRITICA = "critica"


class Asset(BaseModel):
    id: str = Field(default_factory=lambda: f"AST-{uuid.uuid4().hex[:8]}")
    name: str
    type: str  # servidor, endpoint, red, aplicacion, cloud...
    environment: str = "produccion"
    criticality: AssetCriticality = AssetCriticality.MEDIA
    owner: Optional[str] = None
    authorized: bool = True  # el sistema solo debe operar sobre activos autorizados


# ---------------------------------------------------------------------------
# Eventos (unidad mínima ingerida, previa a la correlación)
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    INFO = "info"
    LOW = "baja"
    MEDIUM = "media"
    HIGH = "alta"
    CRITICAL = "critica"


class Event(BaseModel):
    id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:8]}")
    source: str  # jira, edr, firewall, cloud, manual...
    external_id: Optional[str] = None
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    event_type: str = "generico"
    severity: Severity = Severity.INFO
    summary: str
    description: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    incident_id: Optional[str] = None  # se rellena al correlacionar
    threat_ids: List[int] = Field(default_factory=list)  # ids de siem/threats_catalog.py, ver siem/threat_detection.py


# ---------------------------------------------------------------------------
# Incidentes (módulos 3 y 4)
# ---------------------------------------------------------------------------
class IncidentStatus(str, Enum):
    ABIERTO = "abierto"
    EN_INVESTIGACION = "en_investigacion"
    RESUELTO = "resuelto"


class TimelineEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    actor: str  # "sistema", "IA", o nombre/usuario
    description: str


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8]}")
    title: str
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.ABIERTO
    description: str = ""
    affected_assets: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    timeline: List[TimelineEntry] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    risk_score: int = 0  # 0-100
    threat_ids: List[int] = Field(default_factory=list)  # unión de los threat_ids de sus eventos
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    # Cuándo pasó a resuelto (None si sigue abierto o se reabrió). Junto con
    # created_at da el tiempo de resolución que muestra el dashboard.
    resolved_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Inteligencia de amenazas (módulo 5, stub)
# ---------------------------------------------------------------------------
class IOC(BaseModel):
    id: str = Field(default_factory=lambda: f"IOC-{uuid.uuid4().hex[:8]}")
    type: str  # ip, domain, hash, url
    value: str
    campaign: Optional[str] = None
    ttps: List[str] = Field(default_factory=list)  # p.ej. MITRE ATT&CK IDs
    confidence: str = "media"  # baja, media, alta
    # Id de la IP Access Rule real en Cloudflare cuando este IOC viene de un
    # bloqueo confirmado por Praxia Active Defense con conector real (ver
    # siem/cloudflare_firewall.py) -- None si es simulado o añadido a mano.
    cf_rule_id: Optional[str] = None
    # Acción de Active Defense que generó esta entrada (BLOCK/RATE_LIMIT/
    # CHALLENGE/HONEYPOT, ver siem/active_defense.py::RESPONSE_ACTIONS).
    # "BLOCK" por defecto porque las entradas añadidas a mano vía POST
    # /blacklist siempre crean (o intentan crear) un bloqueo real, igual que
    # antes de que existiera este campo. RATE_LIMIT y HONEYPOT lo usan para
    # saber qué IPs debe incluir la regla compartida de Cloudflare (una sola
    # regla de rate limiting / redirect por zona, no una por IP -- ver
    # siem/cloudflare_firewall.py::sync_rate_limit_rule / sync_honeypot_rule).
    action: str = "BLOCK"


class WhitelistEntry(BaseModel):
    """IP que Active Defense nunca debe bloquear (ver siem/router/
    active_defense.py::respond) -- p.ej. la propia IP del equipo, un
    proveedor o un escáner de seguridad contratado que si no dispara
    falsos positivos en el WAF."""
    id: str = Field(default_factory=lambda: f"WL-{uuid.uuid4().hex[:8]}")
    ip: str
    reason: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Automatización (módulo 6) — toda ejecución de acción real requiere confirmación
# ---------------------------------------------------------------------------
class AutomationAction(str, Enum):
    NOTIFICAR = "notificar"
    ABRIR_TICKET = "abrir_ticket"
    COMPROBACION = "comprobacion_automatica"
    GENERAR_INFORME = "generar_informe"
    ESCALAR = "escalar"


class AutomationRule(BaseModel):
    id: str = Field(default_factory=lambda: f"RULE-{uuid.uuid4().hex[:8]}")
    name: str
    trigger: str  # p.ej. "severity>=alta"
    action: AutomationAction
    requires_confirmation: bool = True
    enabled: bool = True


# ---------------------------------------------------------------------------
# Informes (módulo 7)
# ---------------------------------------------------------------------------
class ReportType(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class Report(BaseModel):
    id: str = Field(default_factory=lambda: f"REP-{uuid.uuid4().hex[:8]}")
    type: ReportType
    period_start: datetime
    period_end: datetime
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    content: str


# ---------------------------------------------------------------------------
# Chat de IA
# ---------------------------------------------------------------------------
class ChatMessage(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    message: str
    user_role: Role = Role.ANALISTA
    incident_id: Optional[str] = None
    history: List[ChatMessage] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Campañas de concienciación (nuevo): el vector de entrada más común en una
# pyme no es una vulnerabilidad de software, es un empleado. Nota de
# nombres: `IOC.campaign` (arriba) es un string suelto que identifica una
# campaña de un actor de amenaza (p.ej. "APT28"); esto de aquí es un modelo
# distinto, `Campaign`, para campañas DE CONCIENCIACIÓN internas — no hay
# colisión real (son cosas distintas en namespaces distintos) pero queda
# anotado para que no confunda a quien lea el código después.
# ---------------------------------------------------------------------------
class CampaignTopic(str, Enum):
    PHISHING = "phishing"
    CONTRASENAS = "contrasenas"
    INGENIERIA_SOCIAL = "ingenieria_social"
    MANEJO_DATOS = "manejo_datos"
    MALWARE = "malware"
    OTRO = "otro"


class CampaignContentType(str, Enum):
    EMAIL_PHISHING = "email_phishing"  # simulacro real enviado por email
    COMUNICADO = "comunicado"          # texto de concienciación / política
    QUIZ = "quiz"                      # preguntas de evaluación


class CampaignStatus(str, Enum):
    BORRADOR = "borrador"
    ACTIVA = "activa"
    FINALIZADA = "finalizada"


class TargetStatus(str, Enum):
    PENDIENTE = "pendiente"
    ENVIADO = "enviado"
    CLIC = "clic"              # cayó en el enlace del simulacro de phishing
    REPORTADO = "reportado"    # detectó y reportó el simulacro (buen resultado)
    COMPLETADO = "completado"  # el propio empleado marcó como leído/hecho
    VALIDADO = "validado"      # el equipo de seguridad confirmó esa lectura


class CampaignTarget(BaseModel):
    id: str = Field(default_factory=lambda: f"TGT-{uuid.uuid4().hex[:8]}")
    name: str
    email: Optional[str] = None
    department: Optional[str] = None
    status: TargetStatus = TargetStatus.PENDIENTE
    sent_at: Optional[datetime] = None
    clicked_at: Optional[datetime] = None
    reported_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None  # el empleado dice "lo he leído"
    validated_by_security: bool = False
    validated_by: Optional[str] = None
    validated_at: Optional[datetime] = None


class Campaign(BaseModel):
    id: str = Field(default_factory=lambda: f"CAMP-{uuid.uuid4().hex[:8]}")
    name: str
    topic: CampaignTopic = CampaignTopic.OTRO
    content_type: CampaignContentType = CampaignContentType.COMUNICADO
    status: CampaignStatus = CampaignStatus.BORRADOR
    content: Optional[str] = None  # generado por IA o editado a mano
    targets: List[CampaignTarget] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
