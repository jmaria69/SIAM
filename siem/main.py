import asyncio
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from siem.metrics import metrics
from siem.campaign_scheduler import run_scheduler_loop
from siem.config import Settings, settings as default_settings
from siem.database import Base, engine, run_light_migrations
from siem.ingest.cloudflare_scheduler import run_cloudflare_pull_loop
from siem.router.api import router as tickets_router
from siem.router.ai import router as ai_router
from siem.router.automation import router as automation_router
from siem.router.campaigns import router as campaigns_router
from siem.router.incidents import router as incidents_router
from siem.router.monitoring import router as monitoring_router
from siem.router.reports import router as reports_router
from siem.router.threats import router as threats_router
from siem.router.waf import router as waf_router
from siem.router.course_cybersecurity import router as pyme_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Bug real (2026-07-03): esto vivía como Base.metadata.create_all(bind=engine)
    # suelto a nivel de módulo, ejecutándose contra el siem.db REAL en el momento
    # en que cualquiera hiciera `from siem.main import app` — incluido
    # tests/conftest.py. El dependency_override de get_db en los tests solo
    # afecta las sesiones de request; este create_all corría igual contra el
    # motor de producción, y reventó pytest con "attempt to write a readonly
    # database" en cuanto siem.db quedó con permisos no escribibles para el
    # usuario que corre pytest. Aislarlo en el lifespan hace que solo se
    # ejecute cuando uvicorn arranca de verdad — TestClient(app) sin `with`
    # no dispara lifespan, así que los tests ya no tocan el siem.db real.
    Base.metadata.create_all(bind=engine)

    # Migración ligera (2026-07-05, detección de amenazas): create_all de
    # arriba NO añade la columna threat_ids a las tablas events/incidents
    # que ya existían en el siam.db real -- ver el docstring de
    # run_light_migrations en siem/database.py para el porqué completo.
    run_light_migrations(engine)

    # Scheduler de envío automático de campañas (starts_at). Igual que
    # create_all, solo debe correr cuando uvicorn arranca de verdad, no al
    # importar el módulo para tests -- por eso vive aquí y no a nivel de
    # módulo. Se guarda la referencia a la task para que no la recoja el
    # garbage collector (mismo gotcha ya documentado en el simulador de
    # crisis) y se cancela limpiamente al apagar el servidor.
    scheduler_task = asyncio.create_task(
        run_scheduler_loop(default_settings.CAMPAIGN_SCHEDULER_INTERVAL_SECONDS)
    )

    # Pull periódico de Cloudflare WAF (capa cloud del WAAP híbrido). Mismo
    # patrón que el scheduler de campañas: guardamos la referencia para que
    # no la recoja el garbage collector, y la cancelamos limpiamente al
    # apagar. Si CLOUDFLARE_API_TOKEN/ZONE_ID no están configurados, el
    # loop igual arranca pero cada tick no hace nada (ver
    # `run_cloudflare_pull_once`) -- así no hay que meter un if aquí y
    # tampoco se rompe si el usuario decide activar la integración en
    # caliente cambiando el .env y reiniciando.
    cloudflare_pull_task = asyncio.create_task(
        run_cloudflare_pull_loop(default_settings.CLOUDFLARE_PULL_INTERVAL_SECONDS)
    )

    yield
    scheduler_task.cancel()
    cloudflare_pull_task.cancel()


def create_app(settings_: Settings | None = None) -> FastAPI:
    """Factory de la app FastAPI, parametrizada por settings.

    Se extrajo a factory (2026-07-05, gating de /docs en producción) en vez
    de dejar `app = FastAPI(...)` suelto a nivel de módulo, por el mismo
    motivo de fondo que ya documentó el bug del create_all suelto: un valor
    leído a nivel de módulo (aquí, settings_.ENVIRONMENT) se fija en el
    momento del import y `app.dependency_overrides` en los tests NO lo
    afecta, porque dependency_overrides solo intercepta dependencias
    resueltas en tiempo de request (Depends(...)), no argumentos ya
    consumidos por el propio constructor de FastAPI. Por eso un test que
    quiera comprobar "en producción, /docs está desactivado" tiene que
    llamar a create_app(Settings(ENVIRONMENT="production")) directamente,
    en vez de confiar en el override de get_settings vía HTTP.

    docs_url/redoc_url/openapi_url a None desactiva esas rutas por completo
    en FastAPI (404 real, no un 401/403 que además confirmaría que la ruta
    existe) — la mitigación que de verdad importa, más que enmascarar el
    header Server: FastAPI/Uvicorn siguen siendo identificables al instante
    vía /docs si esas rutas quedan activas en un despliegue público.
    """
    settings_ = settings_ or default_settings
    docs_enabled = settings_.ENVIRONMENT != "production"

    app = FastAPI(
        title=settings_.APP_NAME,
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    # --- MASCARADA DE HUELLA DIGITAL (OCULTAR UVICORN/FASTAPI) ---
    # Nota (2026-07-05): esto por sí solo tiene valor limitado como única
    # defensa — con /docs activo (ENVIRONMENT=development) sigue revelando
    # el stack real al instante. El gating de docs_url/redoc_url/openapi_url
    # de arriba es la mitigación que realmente importa; esto queda como capa
    # adicional, no como sustituto.
    @app.middleware("http")
    async def masquerade_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers["Server"] = "Apache/2.4.41 (Unix) OpenSSL/1.1.1d PHP/7.4.3"
        response.headers["X-Powered-By"] = "PHP/7.4.3"
        return response
    # -------------------------------------------------------------

    # --- MÉTRICAS EN VIVO (panel de escalabilidad de praxialabs/admin) ---
    # Cronometra cada request y la registra en la ventana rodante. No se
    # instrumenta el propio endpoint de métricas para no medir el polling.
    @app.middleware("http")
    async def timing_middleware(request: Request, call_next):
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if request.url.path != "/v1/metrics/scalability":
                metrics.record(elapsed_ms, status, request.url.path)

    @app.get("/v1/metrics/scalability", tags=["metrics"])
    async def scalability_metrics():
        """Métricas de escalabilidad en vivo (throughput + latencia)."""
        return {"ts": time.time(), "service": "siam", "traffic": metrics.snapshot()}
    # ---------------------------------------------------------------------

    # CLAUDE.md decía "CORS gestionado en main.py" pero el main.py real no lo
    # tenía configurado (solo la versión antigua app.py, ya no usada). Se añade
    # aquí, que es donde debía estar desde el principio.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings_.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(tickets_router)  # /v1/ingest/jira, /v1/metrics, /v1/tickets (SQLite, ya existía)
    app.include_router(monitoring_router)  # /v1/monitoring/* (módulo 1)
    app.include_router(incidents_router)  # /v1/incidents/* (módulo 3 y 4)
    app.include_router(ai_router)  # /v1/ai/chat (módulo 9)
    app.include_router(automation_router)  # /v1/automation/* (módulo 6)
    app.include_router(reports_router)  # /v1/reports/* (módulos 7 y 8)
    app.include_router(campaigns_router)  # /v1/campaigns/* (campañas de concienciación)
    app.include_router(threats_router)  # /v1/threats/* (catálogo de 30 amenazas + detección)
    app.include_router(waf_router)  # /v1/ingest/waf (WAAP hibrido: Cloudflare + Coraza)
    app.include_router(pyme_router)  # /v1/pyme/* (Ciberseguridad PYME - PDFs del curso)

    return app


app = create_app()

if __name__ == "__main__":
    # Corrección (2026-07-05): este headers=[...] duplicaba contra
    # masquerade_headers_middleware en create_app() -- mismo bug que se
    # encontró y corrigió en GWS/dashboard_api.py. Se deja solo
    # server_header=False (suprime el "Server: uvicorn" real); el valor
    # falso lo pone una única vez el middleware.
    #
    # Corrección 2 (2026-07-05, confirmado con curl -sD- real): con solo
    # server_header=False, "server: uvicorn" seguía colándose en SIEM pero
    # no en CoreOps, con código casi idéntico. Primera teoría (httptools,
    # que trae uvicorn[standard] y CoreOps no) era incorrecta -- forzar
    # http="h11" solo no lo arregló. El culpable real era uvloop (el otro
    # extra que trae uvicorn[standard] y que CoreOps tampoco tiene):
    # forzando loop="asyncio" además de http="h11", el header duplicado
    # desaparece del todo. No profundicé en el porqué exacto de uvloop (no
    # hace falta para resolverlo), pero queda confirmado empíricamente con
    # dos builds limpios, uno fallando y el siguiente -- con este cambio --
    # pasando.
    uvicorn.run(
        app,
        host=default_settings.APP_HOST,
        port=default_settings.APP_PORT,
        server_header=False,
        http="h11",
        loop="asyncio",
    )
