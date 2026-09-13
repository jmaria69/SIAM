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

from siem.active_defense import PATTERN_REPEAT_OFFENDER_EVENTS
from siem.config import Settings
from siem.store import SiemStore

logger = logging.getLogger("siem.attacker_aggregator")

BATCH_SIZE = 2000

# Clave de RuntimeSettingDB (siem/store.py::get_runtime_bool) para el
# override en caliente de PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS -- ver
# siem/router/active_defense.py::auto-honeypot, que es quien lo escribe.
AUTO_HONEYPOT_SETTING_KEY = "auto_honeypot_repeat_offenders"

# A partir de cuántos eventos WAF se intenta el enriquecimiento RDAP de una
# IP -- deliberadamente el mismo umbral que "reincidente"
# (PATTERN_REPEAT_OFFENDER_EVENTS): no tiene sentido gastar una consulta
# RDAP en una IP que probablemente sea ruido de un único escaneo.
INTEL_LOOKUP_THRESHOLD = PATTERN_REPEAT_OFFENDER_EVENTS


def aggregate_once(store: SiemStore, batch_size: int = BATCH_SIZE) -> int:
    """Un solo tick, aislado para poder testearlo de forma síncrona y
    determinista -- mismo criterio que `run_due_campaigns_once`."""
    return store.aggregate_attacker_profiles(batch_size=batch_size)


def apply_auto_responses(store: SiemStore, settings: Settings) -> list[str]:
    """Segunda pasada tras aggregate_once(): reacciona a los perfiles ya
    actualizados en vez de re-derivar nada de los eventos crudos.

    Dos automatismos independientes, cada uno con su propio flag porque
    tienen implicaciones muy distintas (ver siem/config.py):

    1. Auto-honeypot de reincidentes (PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS,
       False por defecto -- a diferencia de la consulta RDAP, esto sí
       modifica de verdad el firewall sin que un humano confirme esa IP en
       concreto). Reutiliza el mismo umbral que ya pinta "reincidente" en el
       dashboard (pattern_flags/PATTERN_REPEAT_OFFENDER_EVENTS) y el mismo
       camino de ejecución que /respond (apply_response_action), así un
       atacante auto-honeypoteado queda indistinguible en el dashboard de
       uno bloqueado a mano.
    2. Enriquecimiento WHOIS/RDAP (PRAXIA_IP_INTEL_ENABLED, True por
       defecto -- solo lectura, sin credenciales, sin efectos secundarios).

    Devuelve las IPs sobre las que se actuó (solo para logging/tests).
    """
    from siem.response_actions import apply_response_action

    acted: list[str] = []

    # Override en caliente desde el dashboard (Ajustes del panel Active
    # Defense, ver siem/router/active_defense.py::auto-honeypot) -- si nadie
    # lo ha tocado, get_runtime_bool devuelve None y se usa el valor de
    # .env de siempre.
    auto_honeypot = store.get_runtime_bool(AUTO_HONEYPOT_SETTING_KEY)
    if auto_honeypot is None:
        auto_honeypot = settings.PRAXIA_AUTO_HONEYPOT_REPEAT_OFFENDERS

    if settings.PRAXIA_ACTIVE_DEFENSE_ENABLED and auto_honeypot:
        blocked_ips = {ioc.value for ioc in store.list_iocs() if ioc.type == "ip"}
        whitelisted_ips = {w.ip for w in store.list_whitelist()}
        for profile in store.list_repeat_offender_profiles(PATTERN_REPEAT_OFFENDER_EVENTS):
            ip = profile["ip"]
            if ip in blocked_ips or ip in whitelisted_ips:
                continue
            apply_response_action(
                ip, "HONEYPOT", store, settings,
                confidence="media", campaign=f"Auto: reincidente ({profile['event_count']} eventos)",
            )
            acted.append(ip)

    if settings.PRAXIA_IP_INTEL_ENABLED:
        from siem.ip_intel import lookup_ip

        for profile in store.list_repeat_offender_profiles(INTEL_LOOKUP_THRESHOLD):
            if profile.get("intel_fetched_at"):
                continue
            result = lookup_ip(profile["ip"]) or {}
            store.save_attacker_intel(
                profile["ip"],
                org=result.get("org"),
                network_name=result.get("network_name"),
                abuse_email=result.get("abuse_email"),
            )

    return acted


async def run_scheduler_loop(interval_seconds: int) -> None:
    from siem.config import get_settings
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
            apply_auto_responses(store, get_settings())
        except Exception:
            logger.exception("Fallo inesperado en el tick del agregador de atacantes")
        finally:
            db.close()
        await asyncio.sleep(interval_seconds)
