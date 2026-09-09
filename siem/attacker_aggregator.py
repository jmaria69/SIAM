"""Agregador incremental de perfiles de atacante (siem/store.py::
AttackerProfileDB).

Por qué existe: `siem/router/active_defense.py::overview()` agrupaba TODOS
los eventos WAF (hasta 5000) en memoria en cada petición -- vale para el
volumen actual (180 IPs distintas) pero no escala si llegan a haber miles.
Peor aún: el dashboard hace polling cada 5s, así que ese recálculo completo
se repetía sin parar aunque no hubiera tráfico nuevo.

En su lugar, `SiemStore.aggregate_attacker_profiles` mantiene un resumen
por IP que se actualiza de forma INCREMENTAL: cada tick solo procesa los
eventos WAF nuevos desde el último cursor guardado
(`AggregatorCursorDB`, en base de datos, no en memoria del proceso -- mismo
motivo que ya documentó `campaign_scheduler.py` sobre `starts_at`: si el
servidor se reinicia, el siguiente tick retoma justo donde lo dejó).

`overview()` llama a `aggregate_once()` de forma SÍNCRONA justo antes de
leer los perfiles, así el dashboard sigue viendo al instante un atacante
recién ingerido (ver test_overview_groups_ingested_waf_events_when_enabled)
sin depender de que el bucle de fondo ya haya hecho tick -- pero el coste
por petición es O(eventos nuevos desde la última vez), no O(eventos
totales). El bucle de fondo (`run_scheduler_loop`, arrancado en el
lifespan de `siem/main.py`, mismo patrón que el scheduler de campañas)
solo hace falta para mantener los perfiles al día cuando nadie tiene el
dashboard abierto -- otros consumidores futuros (alertas, reportes) no
deberían depender de que alguien esté mirando la pantalla.
"""
import asyncio
import logging

from siem.store import SiemStore

logger = logging.getLogger("siem.attacker_aggregator")

BATCH_SIZE = 2000


def aggregate_once(store: SiemStore, batch_size: int = BATCH_SIZE) -> int:
    """Un solo tick, aislado para poder testearlo de forma síncrona y
    determinista -- mismo criterio que `run_due_campaigns_once`."""
    return store.aggregate_attacker_profiles(batch_size=batch_size)


async def run_scheduler_loop(interval_seconds: int) -> None:
    from siem.database import SessionLocal

    while True:
        db = SessionLocal()
        try:
            store = SiemStore(db)
            processed = aggregate_once(store)
            # El lote se llenó del todo -> puede que queden más eventos sin
            # procesar. Sigue drenando sin esperar el intervalo completo,
            # en vez de dejar que se acumule un backlog creciente.
            while processed >= BATCH_SIZE:
                processed = aggregate_once(store)
        except Exception:
            logger.exception("Fallo inesperado en el tick del agregador de atacantes")
        finally:
            db.close()
        await asyncio.sleep(interval_seconds)
