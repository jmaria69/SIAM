"""Praxia Active Defense (módulo premium) -- ver siem/active_defense.py para
la lógica de agrupación/scoring.

Gateado por settings.PRAXIA_ACTIVE_DEFENSE_ENABLED: /status es siempre
accesible (para que el frontend decida si pinta la pestaña sin necesitar ya
la clave del módulo), el resto de rutas devuelve 403 si el cliente no lo
tiene contratado -- gating real, no solo ocultar la pestaña en el frontend.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from siem.active_defense import (
    RESPONSE_ACTIONS,
    WAF_SOURCES,
    compute_threat_score,
    list_attackers,
    list_campaigns,
)
from siem.cloudflare_firewall import (
    ACTION_TO_CF_MODE,
    CloudflareFirewallError,
    create_access_rule,
    delete_access_rule,
    is_configured,
    sync_honeypot_rule,
)
from siem.config import Settings, get_settings
from siem.models import IOC, WhitelistEntry
from siem.router.honeypot import HONEYPOT_PATH
from siem.store import SiemStore, get_store

# Acciones que no usan IP Access Rules (una por IP) sino una única regla
# compartida por zona vía Rulesets API -- ver siem/cloudflare_firewall.py.
# RATE_LIMIT se queda fuera a propósito: el plan actual no permite filtrar
# una regla de rate limiting por IP (ver docstring de cloudflare_firewall.py),
# así que sigue cayendo al camino simulado más abajo.
SHARED_RULE_ACTIONS = ("HONEYPOT",)

router = APIRouter(prefix="/v1/active-defense", tags=["active-defense"])


class WhitelistCreate(BaseModel):
    ip: str
    reason: str | None = None


def _require_enabled(settings: Settings = Depends(get_settings)) -> None:
    if not settings.PRAXIA_ACTIVE_DEFENSE_ENABLED:
        raise HTTPException(status_code=403, detail="Módulo Praxia Active Defense no contratado")


@router.get("/status")
def status(settings: Settings = Depends(get_settings)) -> dict:
    return {"enabled": settings.PRAXIA_ACTIVE_DEFENSE_ENABLED}


def _blocked_ips(store: SiemStore) -> set[str]:
    # La blacklist reutiliza IOC(type="ip") -- ver /respond, que registra ahí
    # cada bloqueo confirmado. No hace falta una tabla nueva para esto.
    return {ioc.value for ioc in store.list_iocs() if ioc.type == "ip"}


def _whitelisted_ips(store: SiemStore) -> set[str]:
    return {w.ip for w in store.list_whitelist()}


def _shared_rule_ips(
    action: str, store: SiemStore, *, add_ip: Optional[str] = None, remove_ip: Optional[str] = None,
) -> set[str]:
    """Todas las IPs con IOC(action=action) vigentes, ajustadas con la que se
    está añadiendo/quitando en esta misma petición (el IOC aún no está
    guardado/borrado en `store` cuando se llama esto -- ver /respond y
    /blacklist/{ioc_id})."""
    ips = {ioc.value for ioc in store.list_iocs() if ioc.type == "ip" and ioc.action == action}
    if add_ip:
        ips.add(add_ip)
    if remove_ip:
        ips.discard(remove_ip)
    return ips


def _sync_shared_rule(action: str, settings: Settings, ips: set[str]) -> None:
    if action == "HONEYPOT":
        sync_honeypot_rule(settings, ips, target_url=f"{settings.CAMPAIGN_BASE_URL}{HONEYPOT_PATH}")


@router.get("/overview", dependencies=[Depends(_require_enabled)])
def overview(store: SiemStore = Depends(get_store)) -> dict:
    waf_events = [e for e in store.list_events() if e.source in WAF_SOURCES]
    attackers = list_attackers(waf_events, blocked_ips=_blocked_ips(store), whitelisted_ips=_whitelisted_ips(store))
    campaigns = list_campaigns(attackers)
    timeline = sorted(waf_events, key=lambda e: e.timestamp)[-30:]

    return {
        "threat_score": compute_threat_score(waf_events),
        "live_attacks": [e.model_dump() for e in waf_events[:20]],
        "attackers": attackers[:50],
        "campaigns": campaigns,
        "timeline": [e.model_dump() for e in timeline],
    }


@router.post("/respond", dependencies=[Depends(_require_enabled)])
def respond(
    ip: str, action: str, confirm: bool = False,
    store: SiemStore = Depends(get_store), settings: Settings = Depends(get_settings),
) -> dict:
    if action not in RESPONSE_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Acción inválida, usa una de {RESPONSE_ACTIONS}")

    if ip in _whitelisted_ips(store):
        raise HTTPException(status_code=409, detail=f"{ip} está en la lista blanca, no se puede bloquear")

    if not confirm:
        return {
            "ejecutado": False,
            "motivo": "Esta acción requiere confirmación explícita del cliente.",
            "accion_propuesta": action,
            "como_confirmar": f"POST /v1/active-defense/respond?ip={ip}&action={action}&confirm=true",
        }

    # Conector real (ver siem/cloudflare_firewall.py): BLOCK/CHALLENGE crean
    # una IP Access Rule propia; HONEYPOT actualiza la única regla compartida
    # de su fase con el conjunto completo de IPs marcadas con esa acción
    # (incluida esta). RATE_LIMIT se queda simulado siempre -- el plan actual
    # no permite filtrar rate limiting por IP. Si el token no está
    # configurado, todo se queda simulado -- una integración opcional nunca
    # debe tumbar el endpoint.
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
            raise HTTPException(status_code=502, detail=f"No se pudo ejecutar '{action}' en Cloudflare: {exc}")
    elif action in SHARED_RULE_ACTIONS and is_configured(settings):
        try:
            ips = _shared_rule_ips(action, store, add_ip=ip)
            _sync_shared_rule(action, settings, ips)
            real = True
            resultado = f"Acción '{action}' ejecutada de verdad en Cloudflare (regla compartida, {len(ips)} IP(s))."
        except CloudflareFirewallError as exc:
            raise HTTPException(status_code=502, detail=f"No se pudo ejecutar '{action}' en Cloudflare: {exc}")

    # Queda registrado como IOC de confianza alta en cualquier caso (real o
    # simulado): así el dashboard de Threat Intel se puebla con atacantes
    # confirmados y overview() pinta el estado "bloqueada" de verdad. Solo
    # lleva cf_rule_id cuando la acción fue BLOCK/CHALLENGE real (RATE_LIMIT/
    # HONEYPOT no crean una regla propia, ver arriba).
    store.add_ioc(IOC(type="ip", value=ip, confidence="alta", cf_rule_id=cf_rule_id, action=action))

    return {
        "ejecutado": True,
        "accion": action,
        "ip": ip,
        "real": real,
        "resultado": resultado,
    }


# ---------------------------------------------------------------------------
# Lista negra (blacklist) -- reutiliza IOC(type="ip"). /respond ya añade una
# entrada al confirmar un bloqueo; estos endpoints permiten gestionarla a
# mano (añadir sin pasar por /respond, o quitar un bloqueo).
# ---------------------------------------------------------------------------
@router.get("/blacklist", dependencies=[Depends(_require_enabled)])
def get_blacklist(store: SiemStore = Depends(get_store)) -> list[dict]:
    return [ioc.model_dump() for ioc in store.list_iocs() if ioc.type == "ip"]


@router.post("/blacklist", dependencies=[Depends(_require_enabled)])
def add_to_blacklist(
    entry: WhitelistCreate, store: SiemStore = Depends(get_store), settings: Settings = Depends(get_settings),
) -> IOC:
    if entry.ip in _whitelisted_ips(store):
        raise HTTPException(status_code=409, detail=f"{entry.ip} está en la lista blanca")

    cf_rule_id = None
    if is_configured(settings):
        try:
            cf_rule_id = create_access_rule(
                settings, ip=entry.ip, mode="block",
                notes=f"SIAM Active Defense: añadido a lista negra a mano ({entry.reason or 'sin motivo'})",
            )
        except CloudflareFirewallError as exc:
            raise HTTPException(status_code=502, detail=f"No se pudo bloquear en Cloudflare: {exc}")

    return store.add_ioc(IOC(type="ip", value=entry.ip, confidence="alta", campaign=entry.reason, cf_rule_id=cf_rule_id))


@router.delete("/blacklist/{ioc_id}", dependencies=[Depends(_require_enabled)])
def remove_from_blacklist(
    ioc_id: str, store: SiemStore = Depends(get_store), settings: Settings = Depends(get_settings),
) -> dict:
    ioc = store.get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail="No encontrado")

    # Si el bloqueo era real, hay que deshacerlo también en Cloudflare -- si
    # no, "desbloquear" en el SOC dejaría la acción de verdad activa en el
    # firewall, contradiciendo lo que muestra el dashboard. BLOCK/CHALLENGE
    # borran su IP Access Rule propia; HONEYPOT recalcula la regla compartida
    # sin esta IP (nunca tiene cf_rule_id, ver /respond).
    if ioc.cf_rule_id and is_configured(settings):
        try:
            delete_access_rule(settings, ioc.cf_rule_id)
        except CloudflareFirewallError as exc:
            raise HTTPException(status_code=502, detail=f"No se pudo desbloquear en Cloudflare: {exc}")
    elif ioc.action in SHARED_RULE_ACTIONS and is_configured(settings):
        try:
            ips = _shared_rule_ips(ioc.action, store, remove_ip=ioc.value)
            _sync_shared_rule(ioc.action, settings, ips)
        except CloudflareFirewallError as exc:
            raise HTTPException(
                status_code=502, detail=f"No se pudo actualizar la regla compartida de {ioc.action} en Cloudflare: {exc}",
            )

    store.remove_ioc(ioc_id)
    return {"eliminado": True}


# ---------------------------------------------------------------------------
# Lista blanca (whitelist) -- IPs que Active Defense nunca debe bloquear
# (p.ej. el propio equipo, un proveedor, un escáner contratado).
# ---------------------------------------------------------------------------
@router.get("/whitelist", dependencies=[Depends(_require_enabled)])
def get_whitelist(store: SiemStore = Depends(get_store)) -> list[WhitelistEntry]:
    return store.list_whitelist()


@router.post("/whitelist", dependencies=[Depends(_require_enabled)])
def add_to_whitelist(entry: WhitelistCreate, store: SiemStore = Depends(get_store)) -> WhitelistEntry:
    return store.add_whitelist_entry(WhitelistEntry(ip=entry.ip, reason=entry.reason))


@router.delete("/whitelist/{entry_id}", dependencies=[Depends(_require_enabled)])
def remove_from_whitelist(entry_id: str, store: SiemStore = Depends(get_store)) -> dict:
    if not store.remove_whitelist_entry(entry_id):
        raise HTTPException(status_code=404, detail="No encontrado")
    return {"eliminado": True}
