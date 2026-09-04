"""Pull de eventos WAF de Cloudflare (capa cloud del WAAP híbrido).

Usa la GraphQL Analytics API de Cloudflare (`firewallEventsAdaptive`), que
funciona en todos los planes incluido Free -- con retención limitada a
24-72h en Free, motivo por el que se pulla a menudo (default 5 min) en vez
de intentar leer histórico largo. En Business/Enterprise se podría cambiar
a Logpush directo, pero para el MVP el pull cabe sobradamente.

No lleva cursor persistente: se pide una ventana temporal (`lookback` >=
intervalo de pull, ver config) y la deduplicación real la hace el propio
`Event.external_id = rayId` a la hora de escribir en `store.add_event`
(SQLite con UNIQUE en external_id). Es más simple y aguanta reinicios sin
perder ni duplicar eventos: el peor caso es reprocesar un evento que ya
correlacionó, que es idempotente.

Normaliza el resultado a `WafEvent` (el modelo del router) para no acoplar
el pipeline al esquema Cloudflare. Si mañana metemos otro origen (Fastly,
AWS WAF), la única pieza que hay que reescribir es esta.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx

from siem.config import Settings, get_settings
from siem.router.waf import WafEvent

logger = logging.getLogger("siem.ingest.cloudflare")

CLOUDFLARE_GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"

# firewallEventsAdaptive: eventos WAF/rate-limit/bot post-mitigación. Es el
# dataset que Cloudflare recomienda para SIEM -- ver docs oficiales de
# GraphQL Analytics. Se pide un máximo de 1000 por query (limitado por CF).
#
# Bug real (2026-09-04): se añadió de una vez un lote de campos de
# enriquecimiento y tumbaron la ingesta entera -- wafAttackScore/
# wafAttackScoreClass, botScore/botScoreSrcName/verifiedBotCategory (add-on
# Bot Management) y ja3Hash/ja4 (fingerprinting TLS) están todos detrás de
# planes de pago que esta zona (Free) no tiene, y a diferencia de un campo
# ausente normal, GraphQL responde con un error de autorización que descarta
# la query COMPLETA (sin resultado parcial), no solo el campo problemático.
# Verificado campo a campo con curl directo contra la API real: de todo el
# enriquecimiento que se intentó añadir, solo clientASNDescription y
# clientRefererHost están disponibles en Free. Cualquier campo nuevo que se
# añada aquí hay que probarlo contra la zona real (curl, no solo leer docs)
# antes de darlo por bueno -- las docs de GraphQL no distinguen qué campos
# requieren qué plan.
_FIREWALL_EVENTS_QUERY = """
query FirewallEvents($zoneTag: string!, $since: Time!, $until: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(
        filter: {datetime_geq: $since, datetime_leq: $until}
        limit: 1000
        orderBy: [datetime_ASC]
      ) {
        rayName
        datetime
        action
        source
        ruleId
        description
        clientIP
        clientCountryName
        clientAsn
        clientRequestHTTPHost
        clientRequestHTTPMethodName
        clientRequestPath
        clientRequestQuery
        userAgent
        clientASNDescription
        clientRefererHost
      }
    }
  }
}
"""


# Mapa acción Cloudflare -> action normalizado del WafEvent. Cloudflare
# emite bastantes acciones ("managed_challenge", "js_challenge", "log",
# "block", "skip"...); las agrupamos en el vocabulario del WafEvent para
# que la severidad derivada (block=HIGH, challenge=MEDIUM, log=LOW) sea
# consistente entre Cloudflare y Coraza.
_ACTION_MAP: dict[str, str] = {
    "block": "block",
    "connectionClose": "block",
    "jschallenge": "challenge",
    "managed_challenge": "challenge",
    "challenge": "challenge",
    "log": "log",
    "allow": "allow",
    "skip": "skip",
    "bypass": "skip",
}


# Mapa "source" de Cloudflare (firewall dataset) -> attack_category del
# WafEvent. Cloudflare no siempre expone la categoría fina (SQLi vs XSS),
# solo el sistema que disparó ("waf", "rateLimit", "botFight", ...). Se
# hace un best-effort: si la descripción menciona SQLi/XSS/LFI/RCE, se
# usa; si no, se cae al nombre del sistema.
_SOURCE_TO_CATEGORY: dict[str, str] = {
    "waf": "web_attack",
    "rateLimit": "ddos",
    "l7ddos": "ddos",
    "firewallRules": "custom_rule",
    "botFight": "scanner",
    "bic": "scanner",
    "hot": "scanner",
    "securityLevel": "reputation",
    "ipReputation": "reputation",
}

_DESCRIPTION_KEYWORDS: list[tuple[str, str]] = [
    ("sql injection", "sqli"),
    ("sqli", "sqli"),
    ("xss", "xss"),
    ("cross-site scripting", "xss"),
    ("path traversal", "lfi"),
    ("lfi", "lfi"),
    ("remote code execution", "rce"),
    ("rce", "rce"),
    ("command injection", "rce"),
    ("scanner", "scanner"),
    ("bot", "scanner"),
]


def _classify_category(source: Optional[str], description: Optional[str]) -> str:
    """Intenta clasificar el ataque en una categoría que case con keywords
    del catálogo. Primero busca en la descripción (más específico), luego
    en el source (menos específico)."""
    haystack = (description or "").lower()
    for needle, cat in _DESCRIPTION_KEYWORDS:
        if needle in haystack:
            return cat
    if source and source in _SOURCE_TO_CATEGORY:
        return _SOURCE_TO_CATEGORY[source]
    return "generic"


def _row_to_waf_event(row: dict[str, Any]) -> WafEvent:
    """Traduce una fila de firewallEventsAdaptive a WafEvent."""
    raw_action = (row.get("action") or "").strip()
    action = _ACTION_MAP.get(raw_action, "log")

    path = row.get("clientRequestPath") or ""
    query = row.get("clientRequestQuery") or ""
    uri = f"{path}{query}" if query else path

    # datetime viene como ISO-8601 con "Z"; fromisoformat no lo traga hasta
    # 3.11 con "Z" al final -- se sustituye por "+00:00" por si el runtime
    # es 3.10 o menor. Se quita el tzinfo tras parsear: el resto del
    # sistema (Event.timestamp, Incident.updated_at) usa datetime.utcnow()
    # naive, y correlate_event resta timestamps directamente -- un aware
    # aqui rompe esa resta con TypeError en cuanto hay un incidente abierto
    # con el que comparar.
    occurred_at: Optional[datetime] = None
    if row.get("datetime"):
        try:
            occurred_at = datetime.fromisoformat(
                str(row["datetime"]).replace("Z", "+00:00")
            ).replace(tzinfo=None)
        except ValueError:
            occurred_at = None

    return WafEvent(
        source="waf-cloudflare",
        external_id=row.get("rayName"),
        occurred_at=occurred_at,
        action=action,  # type: ignore[arg-type]
        rule_id=row.get("ruleId"),
        rule_message=row.get("description"),
        attack_category=_classify_category(row.get("source"), row.get("description")),
        client_ip=row.get("clientIP"),
        country=row.get("clientCountryName"),
        asn=str(row.get("clientAsn")) if row.get("clientAsn") is not None else None,
        host=row.get("clientRequestHTTPHost"),
        method=row.get("clientRequestHTTPMethodName"),
        uri=uri or None,
        user_agent=row.get("userAgent"),
        asn_org=row.get("clientASNDescription"),
        referer_host=row.get("clientRefererHost"),
        raw=row,
    )


async def fetch_firewall_events(
    settings: Optional[Settings] = None,
    lookback_minutes: Optional[int] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> list[WafEvent]:
    """Consulta Cloudflare y devuelve los eventos ya normalizados.

    Si no hay token o zone id configurados, devuelve [] sin ruido -- el
    scheduler lo trata como "no hay nada que ingestar en este tick".
    """
    settings = settings or get_settings()

    if not settings.CLOUDFLARE_API_TOKEN or not settings.CLOUDFLARE_ZONE_ID:
        return []

    lookback = lookback_minutes or settings.CLOUDFLARE_LOOKBACK_MINUTES
    until = datetime.now(timezone.utc)
    since = until - timedelta(minutes=lookback)

    payload = {
        "query": _FIREWALL_EVENTS_QUERY,
        "variables": {
            "zoneTag": settings.CLOUDFLARE_ZONE_ID,
            "since": since.isoformat().replace("+00:00", "Z"),
            "until": until.isoformat().replace("+00:00", "Z"),
        },
    }
    headers = {
        "Authorization": f"Bearer {settings.CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=30.0)
    try:
        response = await client.post(CLOUDFLARE_GRAPHQL_URL, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
    finally:
        if owns_client:
            await client.aclose()

    if data.get("errors"):
        # Cloudflare devuelve HTTP 200 con errors en el body para problemas
        # de permisos/consulta -- hay que mirarlo aparte del raise_for_status.
        logger.warning("Cloudflare GraphQL devolvió errores: %s", data["errors"])
        return []

    zones = (data.get("data") or {}).get("viewer", {}).get("zones") or []
    if not zones:
        return []

    rows = zones[0].get("firewallEventsAdaptive") or []
    return [_row_to_waf_event(r) for r in rows]
