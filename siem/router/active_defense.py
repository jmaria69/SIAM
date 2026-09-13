"""Praxia Active Defense (módulo premium) -- ver siem/active_defense.py para
la lógica de agrupación/scoring.

Gateado por settings.PRAXIA_ACTIVE_DEFENSE_ENABLED: /status es siempre
accesible (para que el frontend decida si pinta la pestaña sin necesitar ya
la clave del módulo), el resto de rutas devuelve 403 si el cliente no lo
tiene contratado -- gating real, no solo ocultar la pestaña en el frontend.
"""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from siem.active_defense import (
    RESPONSE_ACTIONS,
    WAF_SOURCES,
    attacker_from_profile,
    compute_threat_score,
    list_attackers,
    list_campaigns,
)
from siem.attacker_aggregator import AUTO_HONEYPOT_SETTING_KEY, apply_auto_responses
from siem.cloudflare_firewall import CloudflareFirewallError, create_access_rule, is_configured
from siem.config import Settings, get_settings
from siem.models import IOC, WhitelistEntry
from siem.response_actions import apply_response_action, revert_ioc
from siem.store import SiemStore, get_store

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


def _parse_date_range(date_from: Optional[str], date_to: Optional[str]) -> tuple[Optional[datetime], Optional[datetime]]:
    """"YYYY-MM-DD" (lo que manda <input type="date">) a límites de día
    completos en UTC -- date_to es inclusive (23:59:59.999999), si no un
    filtro "hasta hoy" excluiría los eventos de hoy mismo."""
    def _parse(value: Optional[str], *, end_of_day: bool) -> Optional[datetime]:
        if not value:
            return None
        try:
            parsed = datetime.strptime(value, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Fecha inválida: {value!r} (formato esperado YYYY-MM-DD)")
        return parsed + timedelta(days=1, microseconds=-1) if end_of_day else parsed

    parsed_from = _parse(date_from, end_of_day=False)
    parsed_to = _parse(date_to, end_of_day=True)
    if parsed_from and parsed_to and parsed_from > parsed_to:
        raise HTTPException(status_code=422, detail="date_from no puede ser posterior a date_to")
    return parsed_from, parsed_to


@router.get("/overview", dependencies=[Depends(_require_enabled)])
def overview(
    event_limit: int = Query(10, ge=10, le=100),
    attacker_limit: int = Query(10, ge=10, le=100),
    timeline_limit: int = Query(10, ge=10, le=100),
    date_from: Optional[str] = Query(None, description="YYYY-MM-DD, filtra live_attacks/timeline/threat_score/attackers"),
    date_to: Optional[str] = Query(None, description="YYYY-MM-DD, inclusive"),
    store: SiemStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    if event_limit not in (10, 50, 100):
        raise HTTPException(status_code=422, detail="event_limit debe ser 10, 50 o 100")
    if attacker_limit not in (10, 30, 100):
        raise HTTPException(status_code=422, detail="attacker_limit debe ser 10, 30 o 100")
    if timeline_limit not in (10, 50, 100):
        raise HTTPException(status_code=422, detail="timeline_limit debe ser 10, 50 o 100")
    parsed_from, parsed_to = _parse_date_range(date_from, date_to)
    # date_from/date_to acotan los eventos crudos (live_attacks/timeline/
    # threat_score). Sin rango, "attackers" usa el rollup acumulado de
    # siempre (attacker_profiles, sin dimensión de fecha propia) por
    # rendimiento -- ver aggregate_attacker_profiles más abajo. Con rango,
    # se recalcula al vuelo con list_attackers() sobre los eventos ya
    # filtrados, para que la tabla de atacantes refleje de verdad las
    # fechas elegidas (igual que store.attack_metrics() para el dashboard
    # de métricas, pero aquí con la forma que ya espera el frontend).
    waf_events = store.list_events(limit=2000, sources=WAF_SOURCES, date_from=parsed_from, date_to=parsed_to)
    if parsed_from is not None or parsed_to is not None:
        attackers = list_attackers(
            waf_events, blocked_ips=_blocked_ips(store), whitelisted_ips=_whitelisted_ips(store),
        )[:attacker_limit]
    else:
        # Agrupar atacantes ya NO relee eventos crudos en cada petición (no
        # escalaba a miles de IPs distintas, y el dashboard hace polling
        # cada 5s) -- aggregate_attacker_profiles() es incremental (solo
        # procesa eventos WAF nuevos desde el último cursor) y se llama
        # aquí de forma síncrona para que un atacante recién ingerido siga
        # apareciendo al instante. Ver siem/attacker_aggregator.py.
        store.aggregate_attacker_profiles()
        # Ver siem/attacker_aggregator.py::apply_auto_responses -- mismo
        # motivo que aggregate_attacker_profiles() arriba: cubre el hueco
        # entre ticks del bucle de fondo mientras alguien tiene el
        # dashboard abierto, en vez de depender solo del scheduler.
        apply_auto_responses(store, settings)
        profiles = store.list_attacker_profiles(limit=attacker_limit)
        attackers = [
            attacker_from_profile(p, blocked_ips=_blocked_ips(store), whitelisted_ips=_whitelisted_ips(store))
            for p in profiles
        ]
    campaigns = list_campaigns(attackers)
    # waf_events viene ordenado desc (más reciente primero, ver list_events).
    timeline = list(reversed(waf_events))[-timeline_limit:]

    return {
        "threat_score": compute_threat_score(waf_events),
        "live_attacks": [e.model_dump() for e in waf_events[:event_limit]],
        "attackers": attackers,
        "campaigns": campaigns,
        "timeline": [e.model_dump() for e in timeline],
    }


@router.get("/overview/export", dependencies=[Depends(_require_enabled)])
def overview_export(
    date_from: Optional[str] = Query(None, description="YYYY-MM-DD"),
    date_to: Optional[str] = Query(None, description="YYYY-MM-DD, inclusive"),
    store: SiemStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Exporta todos los atacantes (sin límite attacker_limit) para el rango de fechas.
    Usado por el frontend al exportar CSV/PDF para obtener el conjunto completo."""
    parsed_from, parsed_to = _parse_date_range(date_from, date_to)
    waf_events = store.list_events(limit=10000, sources=WAF_SOURCES, date_from=parsed_from, date_to=parsed_to)

    if parsed_from is not None or parsed_to is not None:
        attackers = list_attackers(
            waf_events, blocked_ips=_blocked_ips(store), whitelisted_ips=_whitelisted_ips(store),
        )
    else:
        store.aggregate_attacker_profiles()
        apply_auto_responses(store, settings)
        profiles = store.list_attacker_profiles(limit=1000)
        attackers = [
            attacker_from_profile(p, blocked_ips=_blocked_ips(store), whitelisted_ips=_whitelisted_ips(store))
            for p in profiles
        ]

    return {"attackers": attackers, "date_from": date_from, "date_to": date_to}


@router.get("/metrics", dependencies=[Depends(_require_enabled)])
def metrics(
    date_from: Optional[str] = Query(None, description="YYYY-MM-DD"),
    date_to: Optional[str] = Query(None, description="YYYY-MM-DD, inclusive"),
    store: SiemStore = Depends(get_store),
) -> dict:
    """Dashboard de métricas de ataques: totales, desglose por severidad/
    categoría/país, interacciones con el honeypot y serie temporal diaria,
    todo filtrable por rango de fechas. Ver store.attack_metrics()."""
    parsed_from, parsed_to = _parse_date_range(date_from, date_to)
    result = store.attack_metrics(date_from=parsed_from, date_to=parsed_to)
    result["date_from"] = date_from
    result["date_to"] = date_to
    return result


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

    # Ejecución + registro como IOC compartidos con el auto-honeypot de
    # reincidentes -- ver siem/response_actions.py.
    return apply_response_action(ip, action, store, settings, confidence="alta")


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

    revert_ioc(ioc, store, settings)
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


@router.get("/auto-honeypot", dependencies=[Depends(_require_enabled)])
def get_auto_honeypot(store: SiemStore = Depends(get_store), settings: Settings = Depends(get_settings)) -> dict:
    """Estado efectivo del auto-honeypot de reincidentes (siem/
    attacker_aggregator.py::apply_auto_responses): el override del
    dashboard si existe, si no el valor de .env
    (PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS)."""
    override = store.get_runtime_bool(AUTO_HONEYPOT_SETTING_KEY)
    enabled = override if override is not None else settings.PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS
    return {"enabled": enabled}


@router.put("/auto-honeypot", dependencies=[Depends(_require_enabled)])
def set_auto_honeypot(enabled: bool, store: SiemStore = Depends(get_store)) -> dict:
    """Enciende/apaga el auto-honeypot de reincidentes sin tocar el .env --
    el siguiente tick de apply_auto_responses lo respeta de inmediato."""
    store.set_runtime_bool(AUTO_HONEYPOT_SETTING_KEY, enabled)
    return {"enabled": enabled}
