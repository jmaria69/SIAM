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

RATE_LIMIT no usa Rulesets (fase `http_ratelimit`): verificado a mano contra
la API real (2026-09-04) que en Free (y también en Pro) el `expression` de
una regla de rate limiting solo admite los campos `Path`/`Verified Bot` --
`ip.src` no está permitido ahí (error "not entitled ... an higher Advanced
Rate Limiting plan is required", solo characteristics admite IP, no
filtrar por IP). Sin filtrar por IP en el expression no hay forma de
dirigir la regla solo a los atacantes marcados sin subir a Business+.

En vez de esperar a ese upgrade, RATE_LIMIT se ejecuta de verdad (fase 3,
2026-09-09) contra un producto DISTINTO de Cloudflare que no tiene esa
restricción de plan: el Rate Limiting API de Workers (un binding en tiempo
de ejecución, no una regla de Rulesets). sync_rate_limit_rule sincroniza el
conjunto de IPs marcadas RATE_LIMIT contra un Workers KV namespace; el
Worker desplegado en workers/rate-limiter/ (ver su README) lee esa lista
en cada request y solo aplica el binding de rate limit a las IPs que están
ahí -- el umbral (peticiones/ventana) es estático, vive en el
wrangler.toml del Worker, no aquí, porque el binding no admite cambiarlo
en caliente. Si CLOUDFLARE_ACCOUNT_ID/CLOUDFLARE_RATE_LIMIT_KV_NAMESPACE_ID
no están configurados, el router cae de vuelta a simulado -- mismo
criterio que el resto: una integración opcional nunca debe tumbar el
endpoint.

Requiere CLOUDFLARE_API_TOKEN con permiso "Zone > Firewall Services > Edit"
para BLOCK/CHALLENGE, "Zone > Single Redirect > Edit" + "Account > Account
Rulesets > Edit" para HONEYPOT, y "Account > Workers KV Storage > Edit"
para RATE_LIMIT (permisos añadidos 2026-09-04 y 2026-09-09; sin ellos, las
funciones de sincronización lanzan CloudflareFirewallError igual que
cualquier otro rechazo de la API) y CLOUDFLARE_ZONE_ID. Si el token o el
zone id faltan, el router cae de vuelta al comportamiento simulado -- una
integración opcional nunca debe tumbar el endpoint (mismo criterio que
SMTP/Telegram en siem/config.py).
"""
from __future__ import annotations

import json
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


def is_rate_limit_configured(settings: Settings) -> bool:
    """RATE_LIMIT necesita, además del token/zone de siempre, el account id
    y el KV namespace del Worker (ver docstring del módulo) -- Workers KV
    vive a nivel de cuenta, no de zona, así que no basta con is_configured().
    Separado a propósito: un cliente con BLOCK/CHALLENGE/HONEYPOT ya
    funcionando de verdad no debe ver RATE_LIMIT fallar en vez de simular
    solo porque todavía no ha desplegado el Worker."""
    return bool(
        is_configured(settings)
        and settings.CLOUDFLARE_ACCOUNT_ID
        and settings.CLOUDFLARE_RATE_LIMIT_KV_NAMESPACE_ID
    )


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
            # Guard antibucle: sin él, una IP honeypoteada que pida /admin
            # (después del redirect) vuelve a caer en la regla → 307 → /admin
            # → ... y el señuelo es inalcanzable para su propia víctima.
            "expression": f"{_ip_set_expression('ip.src', ips)} and not http.request.uri.path eq \"/admin\"",
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


# ---------------------------------------------------------------------------
# HONEYPOT -> exención del WAF managed. La fase http_request_firewall_custom
# (reglas custom + IP Access Rules) y http_request_firewall_managed (OWASP)
# pueden bloquear con 403 a una IP honeypoteada ANTES de que llegue al
# señuelo: los ataques a /admin (que el guard del redirect excluye de la
# redirección) y los probes de path-traversal (que la regla custom de WAF
# Hardening tira a block) nunca alcanzan el panel señuelo -> la pestaña
# Honeypot no captura nada. Visto en producción 2026-09-11: 40 IPs honeypoteadas
# generando 831 bloqueos WAF en 7 días. Se resuelve con una regla skip (producto
# "waf") delante de la regla de hardening + un `and not ip.src in {...}` en esa
# regla, para que el tráfico de una IP honeypoteada llegue entero al decoy.
# ---------------------------------------------------------------------------
HONEYPOT_WAF_SKIP_DESCRIPTION = "SIAM Active Defense - HONEYPOT skip WAF (managed ruleset)"
HONEYPOT_TRAVERSAL_DESCRIPTION = "SIAM Active Defense - WAF Hardening (Path Traversal / archivos sensibles)"


def _get_phase_entrypoint(settings: Settings, phase: str) -> list[dict]:
    url = f"{CLOUDFLARE_API_BASE}/zones/{settings.CLOUDFLARE_ZONE_ID}/rulesets/phases/{phase}/entrypoint"
    try:
        resp = httpx.get(url, headers=_headers(settings), timeout=15)
        data = resp.json()
    except httpx.HTTPError as exc:
        raise CloudflareFirewallError(f"Error de red leyendo la fase {phase}: {exc}") from exc
    if not data.get("success"):
        raise CloudflareFirewallError(f"Cloudflare rechazó la lectura de la fase {phase}: {data.get('errors') or data}")
    return data.get("result", {}).get("rules", []) or []


def _is_traversal_hardening_rule(rule: dict) -> bool:
    description = rule.get("description") or ""
    expression = rule.get("expression") or ""
    return description == HONEYPOT_TRAVERSAL_DESCRIPTION or "wp-config" in expression


def _strip_honeypot_ip_guard(expression: str) -> str:
    """Quita un `and not ip.src in {...}` previamente anexado por
    sync_honeypot_waf, para que volver a sincronizar con un set de IPs
    distinto no acumule guards (idempotente, no importa el orden de llamadas)."""
    marker = " and not ip.src in {"
    return expression.split(marker)[0] if marker in expression else expression


def sync_honeypot_waf(settings: Settings, ips: set[str]) -> None:
    """Exime del WAF managed ruleset a las `ips` honeypoteadas.

    Reemplaza la fase `http_request_firewall_custom` completa con la regla
    skip + la regla de WAF Hardening existente (si la hay) ampliada con
    `and not ip.src in {ips}` -- lee la fase antes para preservar cualquier
    otra regla custom del usuario. `ips` vacío quita el skip y restaura la
    regla de hardening original.
    """
    rules = _get_phase_entrypoint(settings, "http_request_firewall_custom")
    new_rules = []
    if ips:
        new_rules.append({
            "description": HONEYPOT_WAF_SKIP_DESCRIPTION,
            # El skip se evalúa en firewall_custom, antes que el managed
            # ruleset; el producto "waf" salta el WAF (OWASP) para estas IPs.
            "expression": _ip_set_expression("ip.src", ips),
            "action": "skip",
            "action_parameters": {"products": ["waf"]},
        })
    for rule in rules:
        if rule.get("description") == HONEYPOT_WAF_SKIP_DESCRIPTION:
            continue  # se reconstruye arriba siempre con el set de IPs actual
        if _is_traversal_hardening_rule(rule):
            expression = _strip_honeypot_ip_guard(rule.get("expression", ""))
            if ips:
                expression = f"{expression} and not {_ip_set_expression('ip.src', ips)}"
            rule["expression"] = expression
        new_rules.append(rule)
    _put_phase_entrypoint(settings, "http_request_firewall_custom", new_rules)


# ---------------------------------------------------------------------------
# RATE_LIMIT -- Workers KV, no Rulesets (ver docstring del módulo para por
# qué). Igual que HONEYPOT: una única clave por cuenta con el conjunto
# completo de IPs vigentes con acción RATE_LIMIT, se recalcula entera cada
# vez que se añade o quita un IOC con esa acción -- ver
# siem/router/active_defense.py::_sync_shared_rule. El Worker de
# workers/rate-limiter/ hace polling de esta clave (con cache corta) y
# aplica su binding de rate limit solo a las IPs que contiene.
# ---------------------------------------------------------------------------
RATE_LIMIT_KV_KEY = "rate-limited-ips"


def sync_rate_limit_rule(settings: Settings, ips: set[str]) -> None:
    """Escribe en Workers KV el conjunto de IPs marcadas RATE_LIMIT.

    Solo la lista de IPs es dinámica -- el umbral (peticiones por ventana)
    vive en el wrangler.toml del Worker, no aquí, porque el binding de Rate
    Limiting de Workers no admite reconfigurarse en caliente vía API (ver
    workers/rate-limiter/README.md si algún día hace falta cambiarlo).
    `ips` vacío deja la clave como lista vacía (nadie limitado), igual que
    sync_honeypot_rule con rules=[].
    """
    url = (
        f"{CLOUDFLARE_API_BASE}/accounts/{settings.CLOUDFLARE_ACCOUNT_ID}"
        f"/storage/kv/namespaces/{settings.CLOUDFLARE_RATE_LIMIT_KV_NAMESPACE_ID}"
        f"/values/{RATE_LIMIT_KV_KEY}"
    )
    # El valor de un KV es texto plano -- el Worker hace JSON.parse() al
    # leerlo (ver src/index.ts). Se manda como body crudo, no como `json=`
    # de httpx, porque aquí el JSON ES el valor a guardar, no una petición
    # con Content-Type negociado por Cloudflare.
    body = json.dumps({"ips": sorted(ips)})

    try:
        resp = httpx.put(url, headers=_headers(settings), content=body, timeout=15)
        data = resp.json()
    except httpx.HTTPError as exc:
        raise CloudflareFirewallError(f"Error de red sincronizando el KV de rate limit: {exc}") from exc

    if not data.get("success"):
        raise CloudflareFirewallError(
            f"Cloudflare rechazó la escritura del KV de rate limit: {data.get('errors') or data}"
        )
