"""Praxia Active Defense — módulo premium opcional (settings.PRAXIA_ACTIVE_DEFENSE_ENABLED).

No es un pipeline nuevo: reutiliza el WAAP híbrido que ya existe en el MVP
(Collector = siem/ingest/cloudflare.py -> siem/router/waf.py, Analyzer =
siem/threat_detection.py + siem/killchain.py) y añade la capa que faltaba
para venderlo como bloque aparte -- agrupar eventos WAF por atacante/
campaña y decidir una respuesta sugerida. client_ip/país/asn/categoría ya
viajan en Event.raw_payload desde waf.py::_to_event.

Response Engine simulado a propósito (mismo criterio que
siem/router/automation.py): no hay conector real a la API de Cloudflare
todavía -- eso es fase 2, ver docs/ARQUITECTURA.md.
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


def list_attackers(events: list[Event]) -> list[dict]:
    """Agrupa eventos WAF por IP de origen."""
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
        attackers.append({
            "ip": ip,
            "country": last.raw_payload.get("country"),
            "asn": last.raw_payload.get("asn"),
            "event_count": len(evs),
            "attack_categories": categories,
            "max_severity": max_sev.value,
            "threat_score": compute_threat_score(evs),
            "suggested_action": suggest_response(max_sev),
            "first_seen": evs[0].timestamp,
            "last_seen": last.timestamp,
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
