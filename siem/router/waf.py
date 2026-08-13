"""Ingesta de eventos WAF/WAAP (Cloudflare cloud + Coraza on-prem).

Diseño deliberado: NO acoplado a un vendor. El payload de entrada es un
`WafEvent` normalizado, y este router se ocupa de traducirlo a `Event` (el
modelo interno) y meterlo por el mismo pipeline que ya existe para
monitoring (`correlate_event` -> `threat_detection` -> `killchain`). Así el
diferenciador de SIAM -- la kill-chain narrada por IA -- se aplica a las
alertas WAF sin duplicar lógica.

Dos productores hoy:
  * `siem/ingest/cloudflare.py` (pull GraphQL periódico, arrancado desde
     `siem/main.py` en el mismo lifespan que `run_scheduler_loop`).
  * `siem/ingest/coraza.py` (fase H2, aún no implementado — leerá el audit
     log JSON del contenedor `waf_proxy` y postará aquí).

Ambos envían el mismo `WafEvent`, así que si mañana metemos un tercer
origen (p.ej. Fastly, AWS WAF) solo hay que escribir su normalizador; este
router no cambia.

El `event_type` que se emite es siempre `waf.<accion>` (waf.blocked,
waf.challenged, waf.log) para que `detect_threats` case por keywords
igual que hoy: "sqli", "xss", "path traversal", etc. ya están en el
catálogo (ids 8, 17, 32) y las nuevas 31/32 cubren scanning y LFI.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from siem.correlation import correlate_event
from siem.models import Asset, Event, Severity
from siem.store import SiemStore, get_store

router = APIRouter(prefix="/v1/ingest", tags=["waf"])


# ---------------------------------------------------------------------------
# Payload normalizado -- lo emiten los productores (Cloudflare, Coraza, ...).
# ---------------------------------------------------------------------------
class WafEvent(BaseModel):
    """Un evento WAF/WAAP ya normalizado.

    Se traduce 1:1 a `Event` en `ingest_waf_event`. Los campos son los que
    todos los WAFs modernos exponen -- el resto del payload crudo del vendor
    va en `raw` y se guarda tal cual en `Event.raw_payload` para poder
    reconstruir el hecho original en el dashboard sin volver a llamar al
    origen.
    """

    source: Literal["waf-cloudflare", "waf-coraza"]
    external_id: Optional[str] = None       # rayId (CF) o transaction id (Coraza)
    occurred_at: Optional[datetime] = None   # timestamp del evento en el WAF, no de ahora

    # Qué pasó
    action: Literal["block", "challenge", "log", "allow", "skip"] = "block"
    rule_id: Optional[str] = None            # 949110 (CRS), CF managed rule id, ...
    rule_message: Optional[str] = None       # descripción legible de la regla
    attack_category: Optional[str] = None    # sqli, xss, lfi, rce, scanner, ddos, bruteforce...

    # Contra qué / desde dónde
    client_ip: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    host: Optional[str] = None               # dominio protegido (siem.praxialabs.com, ...)
    method: Optional[str] = None
    uri: Optional[str] = None
    user_agent: Optional[str] = None

    # Severidad tal como la vio el WAF (opcional; si no viene se deriva de action)
    severity_hint: Optional[Literal["info", "baja", "media", "alta", "critica"]] = None

    raw: Dict[str, Any] = Field(default_factory=dict)


class WafIngestBatch(BaseModel):
    """El pull de Cloudflare devuelve N eventos por tick -- se ingestan en
    lote. Coraza tirando de audit log también, aunque suele ser 1 a 1. Se
    devuelve el número de aceptados/rechazados en vez de la lista de eventos
    para no cargar payloads gigantes en la respuesta del scheduler."""

    events: List[WafEvent]


class WafIngestResult(BaseModel):
    accepted: int
    incident_ids: List[str]


# ---------------------------------------------------------------------------
# Traducción WafEvent -> Event
# ---------------------------------------------------------------------------
_SEVERITY_FROM_ACTION: dict[str, Severity] = {
    "block": Severity.HIGH,
    "challenge": Severity.MEDIUM,
    "log": Severity.LOW,
    "allow": Severity.INFO,
    "skip": Severity.INFO,
}


def _to_event(waf: WafEvent) -> Event:
    """Traduce el evento WAF al `Event` interno. Las keywords para
    detect_threats viven en `event_type` + `summary` + `description`, así
    que se incluye la categoría del ataque y el mensaje de regla ahí --
    NO en raw_payload, que detect_threats no mira."""

    if waf.severity_hint is not None:
        severity = Severity(waf.severity_hint)
    else:
        severity = _SEVERITY_FROM_ACTION.get(waf.action, Severity.LOW)

    # event_type = "waf.<accion>.<categoria>" para que un evento
    # "waf.block.sqli" case tanto por "waf" como por "sqli" en el catálogo.
    category = (waf.attack_category or "generic").lower().replace(" ", "_")
    event_type = f"waf.{waf.action}.{category}"

    host = waf.host or "web-app"
    summary_parts = [
        f"WAF {waf.action.upper()}",
        f"{waf.method or ''} {waf.uri or ''}".strip() or None,
        f"desde {waf.client_ip}" if waf.client_ip else None,
        f"({waf.country})" if waf.country else None,
    ]
    summary = " ".join(p for p in summary_parts if p).strip()

    # description acumula la firma técnica del ataque -- es lo que
    # detect_threats mira para keywords tipo "sqli", "xss", "path traversal".
    description_parts = [
        waf.rule_message,
        f"Regla: {waf.rule_id}" if waf.rule_id else None,
        f"Categoría: {waf.attack_category}" if waf.attack_category else None,
        f"User-Agent: {waf.user_agent}" if waf.user_agent else None,
    ]
    description = " | ".join(p for p in description_parts if p) or None

    return Event(
        source=waf.source,
        external_id=waf.external_id,
        asset_name=host,
        event_type=event_type,
        severity=severity,
        summary=summary or f"WAF {waf.action} en {host}",
        description=description,
        timestamp=waf.occurred_at or datetime.utcnow(),
        raw_payload=waf.raw,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/waf", response_model=WafIngestResult)
def ingest_waf_events(
    batch: WafIngestBatch,
    store: SiemStore = Depends(get_store),
) -> WafIngestResult:
    """Ingesta un lote de eventos WAF (Cloudflare, Coraza, ...) y los
    correlaciona con incidentes existentes o abre uno nuevo por cada activo.

    Reutiliza el mismo pipeline que /v1/monitoring/ingest -- misma lógica de
    asset autoresolve, misma correlación por ventana temporal, misma
    detección de amenazas por keyword, y por tanto misma kill-chain narrada
    en el dashboard.
    """
    incident_ids: list[str] = []

    for waf_event in batch.events:
        event = _to_event(waf_event)

        # Asset autoresolve por nombre (host), mismo patrón que monitoring.
        # Sin esto, cada dominio distinto se quedaría sin asset y no
        # correlacionaría por activo.
        if event.asset_name and not event.asset_id:
            asset: Asset | None = store.get_or_create_asset_by_name(event.asset_name)
            if asset:
                event.asset_id = asset.id

        # Correlacionar ANTES de persistir -- mismo motivo documentado en
        # siem/router/monitoring.py: mutar el objeto después de escribirlo
        # no actualiza la fila.
        incident = correlate_event(store, event)
        store.add_event(event)

        if incident and incident.id not in incident_ids:
            incident_ids.append(incident.id)

    return WafIngestResult(accepted=len(batch.events), incident_ids=incident_ids)
