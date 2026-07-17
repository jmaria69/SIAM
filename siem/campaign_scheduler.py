"""Envío automático programado de campañas a su `starts_at`.

Bucle de polling en segundo plano (arrancado en el `lifespan` de
`siem/main.py`, mismo patrón que `Base.metadata.create_all`): cada
`CAMPAIGN_SCHEDULER_INTERVAL_SECONDS` consulta la base de datos por
campañas vencidas (`SiemStore.list_due_campaigns`) y las envía con la
misma lógica que el botón manual "Enviar campaña"
(`siem.router.campaigns.send_campaign_now`).

Deliberadamente NO sigue el patrón del simulador de crisis
(`siem/simulator.py`, que cuenta los delays con `asyncio.sleep` por cada
paso, en memoria del proceso). Aquí el estado de "qué falta por enviar"
vive enteramente en la fila de la campaña (`starts_at`, `status`,
`content`) en `siem.db`, no en ningún registro en memoria. Si el servidor
se reinicia antes de `starts_at`, no se pierde nada: en cuanto vuelve a
arrancar, el primer tick de este bucle encuentra la campaña vencida
(`starts_at <= ahora`) y la envía igual -- tarde, pero de forma fiable,
en vez de silenciosamente nunca. Esa es la diferencia real entre "solo
en memoria" y "el estado vive en la base de datos", que es justo la
pega que se señaló como pendiente cuando se expuso `starts_at` por
primera vez en el formulario.
"""
import asyncio
import logging
from typing import Optional

from siem.config import Settings, get_settings
from siem.database import SessionLocal
from siem.router.campaigns import send_campaign_now
from siem.store import SiemStore

logger = logging.getLogger("siem.campaign_scheduler")


def run_due_campaigns_once(store: SiemStore, settings: Optional[Settings] = None) -> list[dict]:
    """Un solo tick, aislado de la sesión/asyncio.sleep para poder
    testearlo de forma síncrona y determinista -- mismo criterio que
    `_inject_step` en el simulador de crisis.

    `settings` es opcional a propósito: en producción (`run_scheduler_loop`)
    se usa el `get_settings()` real cacheado. En tests hay que poder pasar
    un `Settings` explícito con `SMTP_HOST=None` -- si no, esta función
    llamaría a `get_settings()` directamente (sin pasar por el
    `dependency_overrides` de FastAPI, que solo protege las requests HTTP)
    y, en cuanto alguien configure SMTP de verdad en `.env`, los tests
    intentarían una conexión SMTP real. Mismo problema que ya se corrigió
    una vez con el proveedor de IA, evitado aquí desde el principio."""
    settings = settings or get_settings()
    resultados = []
    for campaign in store.list_due_campaigns():
        try:
            resultado = send_campaign_now(campaign, store, settings)
            logger.info(
                "Campaña '%s' (%s) enviada automáticamente en su fecha programada: %s",
                campaign.name,
                campaign.id,
                resultado,
            )
            resultados.append(resultado)
        except Exception:
            # Un fallo enviando una campaña no debe tumbar el bucle ni
            # bloquear el envío de las demás campañas vencidas de ese tick.
            logger.exception("Fallo enviando automáticamente la campaña %s", campaign.id)
    return resultados


async def run_scheduler_loop(interval_seconds: int) -> None:
    while True:
        db = SessionLocal()
        try:
            run_due_campaigns_once(SiemStore(db))
        except Exception:
            logger.exception("Fallo inesperado en el tick del scheduler de campañas")
        finally:
            db.close()
        await asyncio.sleep(interval_seconds)
