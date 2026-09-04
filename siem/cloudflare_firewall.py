"""Conector real de Praxia Active Defense contra el firewall de Cloudflare
(fase 2, ver docstring anterior de siem/active_defense.py y
docs/ARQUITECTURA.md).

Dos mecanismos distintos según la acción:

- BLOCK / CHALLENGE -> "IP Access Rules" (`/zones/{zone}/firewall/access_rules/
  rules`), una regla POR IP, vía create_access_rule/delete_access_rule.
  Verificado a mano con curl contra la zona real (2026-09-04):
  allowed_modes: whitelist, block, challenge, js_challenge, managed_challenge.

- HONEYPOT -> Rulesets API, fase `http_request_dynamic_redirect`, vía
  sync_honeypot_rule. El plan Free solo permite UNA regla de este tipo por
  zona (no una por IP como IP Access Rules), así que aquí no hay "una regla
  por IOC": hay una única regla compartida por zona cuyo expression es un
  IP-set (`ip.src in {...}`) con todas las IPs marcadas como HONEYPOT, y se
  recalcula entera (PUT al entrypoint de la fase, que reemplaza la lista
  completa de reglas) cada vez que se añade o quita un IOC con esa acción --
  ver siem/router/active_defense.py::_sync_shared_rule. Redirige (307) al
  panel señuelo servido por el propio SIAM (siem/router/honeypot.py) en vez
  de a un producto de Cloudflare -- no existe un "honeypot" nativo ahí.
  Probado de verdad contra la zona real (2026-09-04, IP de test 198.51.100.1,
  limpiada después).

RATE_LIMIT se queda SIMULADO a propósito, y no es un límite de permisos del
token sino del plan: verificado a mano contra la API real (2026-09-04) que
en Free (y también en Pro) el `expression` de una regla de rate limiting
solo admite los campos `Path`/`Verified Bot` -- `ip.src` no está permitido
ahí (error "not entitled ... an higher Advanced Rate Limiting plan is
required", solo characteristics admite IP, no filtrar por IP). Sin filtrar
por IP en el expression no hay forma de dirigir la regla solo a los
atacantes marcados; hace falta plan Business o superior. Si algún día se
sube de plan, el mismo patrón de sync_honeypot_rule serviría para
sync_rate_limit_rule (fase `http_ratelimit`).

Requiere CLOUDFLARE_API_TOKEN con permiso "Zone > Firewall Services > Edit"
para BLOCK/CHALLENGE, y además "Zone > Single Redirect > Edit" +
"Account > Account Rulesets > Edit" para HONEYPOT (permisos añadidos
2026-09-04; sin ellos, sync_honeypot_rule lanza CloudflareFirewallError
igual que cualquier otro rechazo de la API) y CLOUDFLARE_ZONE_ID. Si el
token o el zone id faltan, el router cae de vuelta al comportamiento
simulado -- una integración opcional nunca debe tumbar el endpoint (mismo
criterio que SMTP/Telegram en siem/config.py).
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from siem.config import Settings

logger = logging.getLogger("siem.cloudflare_firewall")

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"

# Acción de Active Defense -> modo real de IP Access Rules. Ver docstring del
# módulo para por qué RATE_LIMIT/HONEYPOT no están aquí.
ACTION_TO_CF_MODE: dict[str, str] = {
    "BLOCK": "block",
    "CHALLENGE": "managed_challenge",
}


class CloudflareFirewallError(RuntimeError):
    """La API de Cloudflare devolvió success=false o un error de transporte."""


def is_configured(settings: Settings) -> bool:
    return bool(settings.CLOUDFLARE_API_TOKEN and settings.CLOUDFLARE_ZONE_ID)


def _headers(settings: Settings) -> dict:
    return {"Authorization": f"Bearer {settings.CLOUDFLARE_API_TOKEN}", "Content-Type": "application/json"}


def create_access_rule(settings: Settings, ip: str, mode: str, notes: str) -> str:
    """Crea una IP Access Rule real en la zona y devuelve su id.

    Si la IP ya tiene una regla (Cloudflare responde con el error 10009,
    "firewallaccessrules.api.duplicate_of_existing"), se reutiliza la regla
    existente en vez de fallar -- idempotente, para que confirmar la misma
    acción dos veces no rompa nada.
    """
    url = f"{CLOUDFLARE_API_BASE}/zones/{settings.CLOUDFLARE_ZONE_ID}/firewall/access_rules/rules"
    payload = {"mode": mode, "configuration": {"target": "ip", "value": ip}, "notes": notes}

    try:
        resp = httpx.post(url, headers=_headers(settings), json=payload, timeout=15)
        data = resp.json()
    except httpx.HTTPError as exc:
        raise CloudflareFirewallError(f"Error de red contactando con Cloudflare: {exc}") from exc

    if data.get("success"):
        return data["result"]["id"]

    errors = data.get("errors") or []
    if any(err.get("code") == 10009 for err in errors):
        existing_id = _find_existing_rule_id(settings, ip)
        if existing_id:
            logger.info("IP Access Rule ya existía para %s, se reutiliza %s", ip, existing_id)
            return existing_id

    raise CloudflareFirewallError(f"Cloudflare rechazó la regla para {ip}: {errors or data}")


def _find_existing_rule_id(settings: Settings, ip: str) -> Optional[str]:
    url = f"{CLOUDFLARE_API_BASE}/zones/{settings.CLOUDFLARE_ZONE_ID}/firewall/access_rules/rules"
    try:
        resp = httpx.get(url, headers=_headers(settings), params={"configuration.value": ip}, timeout=15)
        data = resp.json()
    except httpx.HTTPError:
        return None
    results = data.get("result") or []
    return results[0]["id"] if results else None


def delete_access_rule(settings: Settings, rule_id: str) -> None:
    """Borra una IP Access Rule real. No lanza si ya no existe (idempotente:
    desbloquear dos veces la misma IP no debe romper el endpoint)."""
    url = f"{CLOUDFLARE_API_BASE}/zones/{settings.CLOUDFLARE_ZONE_ID}/firewall/access_rules/rules/{rule_id}"
    try:
        resp = httpx.delete(url, headers=_headers(settings), timeout=15)
        data = resp.json()
    except httpx.HTTPError as exc:
        raise CloudflareFirewallError(f"Error de red borrando la regla {rule_id}: {exc}") from exc

    if not data.get("success"):
        errors = data.get("errors") or []
        if any(err.get("code") == 10000 for err in errors):
            return  # ya no existía -- no es un fallo real
        raise CloudflareFirewallError(f"Cloudflare no pudo borrar la regla {rule_id}: {errors or data}")


# ---------------------------------------------------------------------------
# HONEYPOT -- Rulesets API, una única regla compartida por zona (ver
# docstring del módulo). `_put_phase_entrypoint` reemplaza SIEMPRE la lista
# entera de reglas de la fase con `rules` -- por eso el caller debe pasar el
# conjunto completo de IPs vigentes con acción HONEYPOT, no solo la que
# cambió. Con `rules=[]` la fase queda vacía (sin regla activa), que es
# justo lo que se quiere cuando ya no queda ninguna IP con esa acción.
# ---------------------------------------------------------------------------
def _ip_set_expression(field: str, ips: set[str]) -> str:
    # IPs sueltas van SIN comillas y separadas por espacios dentro de las
    # llaves -- sintaxis propia del "IP address literal" de Cloudflare
    # (distinta de una lista de strings, que sí lleva comillas). Ver
    # https://developers.cloudflare.com/ruleset-engine/rules-language/values/
    ip_list = " ".join(sorted(ips))
    return f"{field} in {{{ip_list}}}"


def _put_phase_entrypoint(settings: Settings, phase: str, rules: list[dict]) -> None:
    url = f"{CLOUDFLARE_API_BASE}/zones/{settings.CLOUDFLARE_ZONE_ID}/rulesets/phases/{phase}/entrypoint"
    try:
        resp = httpx.put(url, headers=_headers(settings), json={"rules": rules}, timeout=15)
        data = resp.json()
    except httpx.HTTPError as exc:
        raise CloudflareFirewallError(f"Error de red sincronizando la fase {phase}: {exc}") from exc

    if not data.get("success"):
        raise CloudflareFirewallError(f"Cloudflare rechazó la regla de la fase {phase}: {data.get('errors') or data}")


def sync_honeypot_rule(settings: Settings, ips: set[str], target_url: str) -> None:
    """Reemplaza la única regla de redirección dinámica de la zona para que
    las `ips` marcadas como HONEYPOT caigan en `target_url` (el panel señuelo
    de siem/router/honeypot.py) en vez de en el sitio real. `ips` vacío borra
    la regla."""
    rules = []
    if ips:
        rules = [{
            "description": "SIAM Active Defense - HONEYPOT",
            "expression": _ip_set_expression("ip.src", ips),
            "action": "redirect",
            "action_parameters": {
                "from_value": {
                    "target_url": {"value": target_url},
                    "status_code": 307,
                    "preserve_query_string": False,
                }
            },
        }]
    _put_phase_entrypoint(settings, "http_request_dynamic_redirect", rules)
