"""Bucle de pull periódico de eventos WAF Cloudflare.

Mismo patrón que `siem/campaign_scheduler.py`: se arranca en el `lifespan`
de `siem/main.py`, cada N segundos pide eventos a Cloudflare y los mete por
el pipeline de correlación/kill-chain reutilizando el endpoint interno de
ingesta WAF.

No se hace HTTP self-call: se invoca `ingest_waf_events` directamente con
una `SiemStore` propia -- así el bucle no depende de que la app esté
escuchando en su puerto y no hay overhead ni riesgo de deadlock por
recursión HTTP contra el mismo proceso.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from siem.config import Settings, get_settings
from siem.database import SessionLocal
from siem.ingest.cloudflare import fetch_firewall_events
from siem.router.waf import WafIngestBatch, ingest_waf_events
from siem.store import SiemStore

logger = logging.getLogger("siem.ingest.cloudflare_scheduler")


async def run_cloudflare_pull_once(settings: Optional[Settings] = None) -> int:
    """Un solo tick, aislado para poder testearlo síncrono -- mismo criterio
    que `run_due_campaigns_once`. Devuelve el número de eventos ingestados
    (0 si Cloudflare no está configurado o no hay nada en la ventana).
    """
    settings = settings or get_settings()

    if not settings.CLOUDFLARE_API_TOKEN or not settings.CLOUDFLARE_ZONE_ID:
        return 0

    try:
        events = await fetch_firewall_events(settings)
    except Exception:
        # Un fallo de red o de auth no debe tumbar el bucle -- se registra
        # y se reintenta en el próximo tick, mismo criterio que el
        # scheduler de campañas.
        logger.exception("Fallo consultando Cloudflare firewallEventsAdaptive")
        return 0

    if not events:
        return 0

    db = SessionLocal()
    try:
        store = SiemStore(db)
        result = ingest_waf_events(WafIngestBatch(events=events), store)
        logger.info(
            "Cloudflare pull: %d eventos WAF ingestados, incidentes tocados: %s",
            result.accepted,
            result.incident_ids,
        )
        return result.accepted
    finally:
        db.close()


async def run_cloudflare_pull_loop(interval_seconds: int) -> None:
    while True:
        try:
            await run_cloudflare_pull_once()
        except Exception:
            logger.exception("Fallo inesperado en el tick del pull de Cloudflare")
        await asyncio.sleep(interval_seconds)
