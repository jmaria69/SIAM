"""Praxia Active Defense (módulo premium) -- ver siem/active_defense.py para
la lógica de agrupación/scoring.

Gateado por settings.PRAXIA_ACTIVE_DEFENSE_ENABLED: /status es siempre
accesible (para que el frontend decida si pinta la pestaña sin necesitar ya
la clave del módulo), el resto de rutas devuelve 403 si el cliente no lo
tiene contratado -- gating real, no solo ocultar la pestaña en el frontend.
"""
from fastapi import APIRouter, Depends, HTTPException

from siem.active_defense import (
    RESPONSE_ACTIONS,
    WAF_SOURCES,
    compute_threat_score,
    list_attackers,
    list_campaigns,
)
from siem.config import Settings, get_settings
from siem.models import IOC
from siem.store import SiemStore, get_store

router = APIRouter(prefix="/v1/active-defense", tags=["active-defense"])


def _require_enabled(settings: Settings = Depends(get_settings)) -> None:
    if not settings.PRAXIA_ACTIVE_DEFENSE_ENABLED:
        raise HTTPException(status_code=403, detail="Módulo Praxia Active Defense no contratado")


@router.get("/status")
def status(settings: Settings = Depends(get_settings)) -> dict:
    return {"enabled": settings.PRAXIA_ACTIVE_DEFENSE_ENABLED}


@router.get("/overview", dependencies=[Depends(_require_enabled)])
def overview(store: SiemStore = Depends(get_store)) -> dict:
    waf_events = [e for e in store.list_events() if e.source in WAF_SOURCES]
    attackers = list_attackers(waf_events)
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
def respond(ip: str, action: str, confirm: bool = False, store: SiemStore = Depends(get_store)) -> dict:
    if action not in RESPONSE_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Acción inválida, usa una de {RESPONSE_ACTIONS}")

    if not confirm:
        return {
            "ejecutado": False,
            "motivo": "Esta acción requiere confirmación explícita del cliente.",
            "accion_propuesta": action,
            "como_confirmar": f"POST /v1/active-defense/respond?ip={ip}&action={action}&confirm=true",
        }

    # Simulado a propósito, mismo criterio que siem/router/automation.py --
    # sin conector real a la API de Cloudflare todavía (fase 2, ver
    # docs/ARQUITECTURA.md). Queda registrado como IOC de confianza alta:
    # así el dashboard de Threat Intel (IOC, ya existente en el modelo)
    # empieza a poblarse con atacantes confirmados en vez de quedar vacío.
    store.add_ioc(IOC(type="ip", value=ip, confidence="alta"))

    return {
        "ejecutado": True,
        "accion": action,
        "ip": ip,
        "resultado": f"Acción '{action}' simulada correctamente sobre {ip}.",
    }
