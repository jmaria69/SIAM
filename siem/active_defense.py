"""Praxia Active Defense — módulo premium opcional (settings.PRAXIA_ACTIVE_DEFENSE_ENABLED).

No es un pipeline nuevo: reutiliza el WAAP híbrido que ya existe en el MVP
(Collector = siem/ingest/cloudflare.py -> siem/router/waf.py, Analyzer =
siem/threat_detection.py + siem/killchain.py) y añade la capa que faltaba
para venderlo como bloque aparte -- agrupar eventos WAF por atacante/
campaña y decidir una respuesta sugerida. client_ip/país/asn/categoría ya
viajan en Event.raw_payload desde waf.py::_to_event.

Este módulo solo decide QUÉ acción sugerir (suggest_response, determinista
por severidad) y agrupa atacantes/campañas -- la ejecución real contra
Cloudflare (fase 2, ya implementada) vive en siem/router/active_defense.py +
siem/cloudflare_firewall.py. Si no hay CLOUDFLARE_API_TOKEN/ZONE_ID
configurados, el router cae de vuelta a simulado (mismo criterio que
siem/router/automation.py): una integración opcional nunca debe tumbar el
endpoint.
"""
from collections import defaultdict

from siem.models import Event, Severity
from siem.risk import SEVERITY_WEIGHT

RESPONSE_ACTIONS = ["BLOCK", "RATE_LIMIT", "CHALLENGE", "HONEYPOT"]

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

_ACTION_BY_SEVERITY = {
    Severity.CRITICAL: "BLOCK",
    Severity.HIGH: "RATE_LIMIT",
    Severity.MEDIUM: "CHALLENGE",
    Severity.LOW: "HONEYPOT",
    Severity.INFO: "HONEYPOT",
}

WAF_SOURCES = ("waf-cloudflare", "waf-coraza")


def suggest_response(max_severity: Severity) -> str:
    """Decisión determinista (sin IA), mismo criterio que threat_detection.py."""
    return _ACTION_BY_SEVERITY.get(max_severity, "CHALLENGE")


def _max_severity(events: list[Event]) -> Severity:
    return max((e.severity for e in events), key=_SEVERITY_ORDER.index)


def compute_threat_score(events: list[Event]) -> int:
    """0-100, misma fórmula/saturación que risk.calculate_global_risk."""
    if not events:
        return 0
    return min(100, sum(SEVERITY_WEIGHT.get(e.severity, 5) for e in events))


def list_attackers(
    events: list[Event],
    blocked_ips: set[str] | None = None,
    whitelisted_ips: set[str] | None = None,
) -> list[dict]:
    """Agrupa eventos WAF por IP de origen.

    `blocked_ips`/`whitelisted_ips` los calcula el router cruzando
    store.list_iocs() (bloqueos confirmados vía /respond) y
    store.list_whitelist() -- así el dashboard puede pintar si un atacante
    está realmente bloqueado en vez de solo "sugerido"."""
    blocked_ips = blocked_ips or set()
    whitelisted_ips = whitelisted_ips or set()

    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source not in WAF_SOURCES:
            continue
        ip = e.raw_payload.get("client_ip")
        if ip:
            by_ip[ip].append(e)

    attackers = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        last = evs[-1]
        max_sev = _max_severity(evs)
        categories = sorted({
            e.raw_payload.get("attack_category") for e in evs if e.raw_payload.get("attack_category")
        })

        if ip in whitelisted_ips:
            status = "lista_blanca"
        elif ip in blocked_ips:
            status = "bloqueada"
        else:
            status = "activa"

        attackers.append({
            "ip": ip,
            "country": last.raw_payload.get("country"),
            "asn": last.raw_payload.get("asn"),
            "asn_org": last.raw_payload.get("asn_org"),
            "event_count": len(evs),
            "attack_categories": categories,
            "max_severity": max_sev.value,
            "threat_score": compute_threat_score(evs),
            "suggested_action": suggest_response(max_sev),
            "status": status,
            "first_seen": evs[0].timestamp,
            "last_seen": last.timestamp,
            # Huella del atacante -- lo más cercano a "identidad" que existe
            # de verdad para tráfico remoto (ver comentario en waf.py sobre
            # por qué no hay MAC). Se toma del evento más reciente. JA3/JA4,
            # bot score y WAF attack score se probaron y se descartaron: son
            # de planes de pago que esta zona no tiene (ver waf.py).
            "last_host": last.raw_payload.get("host"),
            "last_uri": last.raw_payload.get("uri"),
            "last_user_agent": last.raw_payload.get("user_agent"),
            "referer_host": last.raw_payload.get("referer_host"),
        })
    attackers.sort(key=lambda a: a["threat_score"], reverse=True)
    return attackers


def list_campaigns(attackers: list[dict]) -> list[dict]:
    """Una campaña = actividad coordinada, sin ML: >=2 IPs distintas (o una
    sola muy activa) compartiendo la misma categoría de ataque."""
    by_category: dict[str, list[dict]] = defaultdict(list)
    for a in attackers:
        for cat in (a["attack_categories"] or ["generic"]):
            by_category[cat].append(a)

    campaigns = []
    for cat, group in by_category.items():
        total_events = sum(a["event_count"] for a in group)
        if len(group) < 2 and total_events < 5:
            continue
        campaigns.append({
            "name": f"Campaña {cat}",
            "attack_category": cat,
            "attacker_count": len(group),
            "event_count": total_events,
            "threat_score": min(100, sum(a["threat_score"] for a in group)),
            "attacker_ips": [a["ip"] for a in group],
        })
    campaigns.sort(key=lambda c: c["threat_score"], reverse=True)
    return campaigns
