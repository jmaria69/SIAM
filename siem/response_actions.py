"""Ejecución real/simulada de una acción de respuesta de Praxia Active
Defense (BLOCK/RATE_LIMIT/CHALLENGE/HONEYPOT) + registro como IOC.

Extraído de siem/router/active_defense.py (2026-09-09) para que tanto el
endpoint manual (/respond, siempre con confirm=True explícito de un humano)
como la detección automática de reincidentes
(siem/attacker_aggregator.py::apply_auto_responses) compartan el mismo
camino de código -- así un atacante auto-honeypoteado se ve en el dashboard
exactamente igual (mismo IOC, mismo estado "bloqueada") que uno que un
analista bloqueó a mano, sin duplicar la integración con Cloudflare.
"""
from __future__ import annotations

from typing import Optional

from siem.cloudflare_firewall import (
    ACTION_TO_CF_MODE,
    CloudflareFirewallError,
    create_access_rule,
    delete_access_rule,
    is_configured,
    is_rate_limit_configured,
    sync_honeypot_rule,
    sync_rate_limit_rule,
)
from siem.config import Settings
from siem.models import IOC
from siem.router.honeypot import HONEYPOT_PATH
from siem.store import SiemStore

# Acciones que no usan IP Access Rules (una por IP) sino un único recurso
# compartido con el conjunto completo de IPs vigentes -- ver
# siem/cloudflare_firewall.py. HONEYPOT usa una regla de Rulesets por zona;
# RATE_LIMIT usa un Workers KV namespace por cuenta. Cada acción tiene su
# propia comprobación de "está configurado" -- ver shared_rule_configured --
# porque RATE_LIMIT necesita credenciales adicionales (account id + KV
# namespace) que HONEYPOT no.
SHARED_RULE_ACTIONS = ("HONEYPOT", "RATE_LIMIT")


def shared_rule_configured(action: str, settings: Settings) -> bool:
    if action == "HONEYPOT":
        return is_configured(settings)
    if action == "RATE_LIMIT":
        return is_rate_limit_configured(settings)
    return False


def sync_shared_rule(action: str, settings: Settings, ips: set[str]) -> None:
    if action == "HONEYPOT":
        sync_honeypot_rule(settings, ips, target_url=f"{settings.CAMPAIGN_BASE_URL}{HONEYPOT_PATH}")
    elif action == "RATE_LIMIT":
        sync_rate_limit_rule(settings, ips)


def shared_rule_ips(
    action: str, store: SiemStore, *, add_ip: Optional[str] = None, remove_ip: Optional[str] = None,
) -> set[str]:
    """Todas las IPs con IOC(action=action) vigentes, ajustadas con la que se
    está añadiendo/quitando en esta misma llamada (el IOC aún no está
    guardado/borrado en `store` cuando se llama esto)."""
    ips = {ioc.value for ioc in store.list_iocs() if ioc.type == "ip" and ioc.action == action}
    if add_ip:
        ips.add(add_ip)
    if remove_ip:
        ips.discard(remove_ip)
    return ips


def revert_ioc(ioc: IOC, store: SiemStore, settings: Settings) -> None:
    """Deshace en Cloudflare lo que dejó activo un IOC (usado tanto al
    desbloquear como al reemplazarlo por una acción distinta) -- si no, el
    SOC vería el dashboard "limpio" mientras la acción de verdad sigue
    activa en el firewall. BLOCK/CHALLENGE borran su IP Access Rule propia;
    HONEYPOT/RATE_LIMIT recalculan su recurso compartido sin esta IP (nunca
    tienen cf_rule_id)."""
    from fastapi import HTTPException

    if ioc.cf_rule_id and is_configured(settings):
        try:
            delete_access_rule(settings, ioc.cf_rule_id)
        except CloudflareFirewallError as exc:
            raise HTTPException(status_code=502, detail=f"No se pudo desbloquear en Cloudflare: {exc}")
    elif ioc.action in SHARED_RULE_ACTIONS and shared_rule_configured(ioc.action, settings):
        try:
            ips = shared_rule_ips(ioc.action, store, remove_ip=ioc.value)
            sync_shared_rule(ioc.action, settings, ips)
        except CloudflareFirewallError as exc:
            raise HTTPException(
                status_code=502, detail=f"No se pudo actualizar la regla compartida de {ioc.action} en Cloudflare: {exc}",
            )


def apply_response_action(
    ip: str, action: str, store: SiemStore, settings: Settings, *, confidence: str = "alta", campaign: Optional[str] = None,
) -> dict:
    """Ejecuta `action` sobre `ip` (real si hay credenciales configuradas,
    si no simulado) y la registra como IOC. NO comprueba lista blanca ni
    exige confirmación -- eso es responsabilidad del caller: el endpoint
    /respond la pide de un humano antes de llamar aquí; el auto-honeypot de
    reincidentes (siem/attacker_aggregator.py) la sustituye por el umbral
    determinista de active_defense.PATTERN_REPEAT_OFFENDER_EVENTS."""
    cf_mode = ACTION_TO_CF_MODE.get(action)
    cf_rule_id = None
    real = False
    resultado = f"Acción '{action}' simulada correctamente sobre {ip} (sin conector real para esta acción)."

    if cf_mode and is_configured(settings):
        try:
            cf_rule_id = create_access_rule(
                settings, ip=ip, mode=cf_mode,
                notes=f"SIAM Active Defense: {action} confirmado desde el SOC",
            )
            real = True
            resultado = f"Acción '{action}' ejecutada de verdad en Cloudflare (IP Access Rule {cf_rule_id})."
        except CloudflareFirewallError as exc:
            from fastapi import HTTPException
            raise HTTPException(status_code=502, detail=f"No se pudo ejecutar '{action}' en Cloudflare: {exc}")
    elif action in SHARED_RULE_ACTIONS and shared_rule_configured(action, settings):
        try:
            ips = shared_rule_ips(action, store, add_ip=ip)
            sync_shared_rule(action, settings, ips)
            real = True
            resultado = f"Acción '{action}' ejecutada de verdad en Cloudflare (regla compartida, {len(ips)} IP(s))."
        except CloudflareFirewallError as exc:
            from fastapi import HTTPException
            raise HTTPException(status_code=502, detail=f"No se pudo ejecutar '{action}' en Cloudflare: {exc}")

    # Queda registrado como IOC en cualquier caso (real o simulado): así el
    # dashboard de Threat Intel se puebla con atacantes confirmados y
    # overview() pinta el estado "bloqueada" de verdad. Si la IP ya tenía un
    # IOC, se sustituye en vez de acumular una entrada por acción -- si la
    # acción anterior dejó algo activo en Cloudflare y la nueva es distinta,
    # se deshace primero.
    existing = next((ioc for ioc in store.list_iocs() if ioc.type == "ip" and ioc.value == ip), None)
    if existing is not None:
        if existing.action != action:
            revert_ioc(existing, store, settings)
        store.remove_ioc(existing.id)
    store.add_ioc(IOC(type="ip", value=ip, confidence=confidence, campaign=campaign, cf_rule_id=cf_rule_id, action=action))

    return {
        "ejecutado": True,
        "accion": action,
        "ip": ip,
        "real": real,
        "resultado": resultado,
    }
