"""Enriquecimiento WHOIS/RDAP de IPs reincidentes (siem/attacker_aggregator.py).

RDAP (RFC 9083) es el reemplazo moderno de WHOIS: una API JSON estándar, sin
clave ni cuota propia, que devuelve el registro real de la IP (organización,
nombre de red, contacto de abuso) directamente del registro regional que
corresponda (ARIN/RIPE/APNIC/LACNIC/AFRINIC). Se usa el bootstrap público
https://rdap.org/ip/{ip}, que redirige automáticamente al registro correcto
-- no hace falta saber de antemano cuál es. Formato de respuesta verificado
a mano contra rdap.org (2026-09-09).

Solo se llama una vez por IP (ver intel_fetched_at en AttackerProfileDB,
siem/attacker_aggregator.py::apply_auto_responses) y solo para reincidentes
confirmados, no para todo el tráfico. Fail-open como cualquier otra
integración opcional de este proyecto: cualquier error de red, timeout o
respuesta inesperada devuelve None sin romper el agregador.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger("siem.ip_intel")

RDAP_BOOTSTRAP_URL = "https://rdap.org/ip/{ip}"


def _vcard_value(vcard_array: Any, *field_names: str) -> Optional[str]:
    """vcardArray tiene la forma ["vcard", [[campo, params, tipo, valor], ...]]
    -- ver RFC 7095. Devuelve el primer valor cuyo campo esté en
    `field_names`, en el orden dado (para poder preferir "fn" sobre "org",
    por ejemplo)."""
    if not vcard_array or len(vcard_array) < 2:
        return None
    entries = {entry[0]: entry[3] for entry in vcard_array[1] if len(entry) >= 4}
    for name in field_names:
        value = entries.get(name)
        if isinstance(value, str) and value:
            return value
    return None


def _find_entity_by_role(entities: list[dict], role: str) -> Optional[dict]:
    for entity in entities or []:
        if role in (entity.get("roles") or []):
            return entity
    return None


def lookup_ip(ip: str, *, timeout: float = 8.0) -> Optional[dict]:
    """Consulta RDAP para `ip` y devuelve un resumen listo para guardar en
    AttackerProfileDB, o None si no hay datos útiles o la consulta falló."""
    try:
        resp = httpx.get(
            RDAP_BOOTSTRAP_URL.format(ip=ip),
            timeout=timeout,
            follow_redirects=True,
            headers={"Accept": "application/rdap+json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.info("RDAP lookup falló para %s: %s", ip, exc)
        return None

    entities = data.get("entities") or []
    registrant = _find_entity_by_role(entities, "registrant")
    abuse_entity = _find_entity_by_role(entities, "abuse")
    # El contacto de abuso a veces cuelga de un entity anidado dentro del
    # registrant en vez de venir como entity propia de nivel superior.
    if abuse_entity is None and registrant is not None:
        abuse_entity = _find_entity_by_role(registrant.get("entities") or [], "abuse")

    result = {
        "org": _vcard_value(registrant.get("vcardArray") if registrant else None, "fn", "org"),
        "network_name": data.get("name"),
        "abuse_email": _vcard_value(abuse_entity.get("vcardArray") if abuse_entity else None, "email"),
    }
    if not any(result.values()):
        return None
    return result
