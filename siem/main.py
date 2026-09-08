import asyncio
import re
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from siem.metrics import metrics
from siem.campaign_scheduler import run_scheduler_loop
from siem.config import Settings, settings as default_settings
from siem.database import Base, engine, run_light_migrations
from siem.ingest.cloudflare_scheduler import run_cloudflare_pull_loop
from siem.router.api import router as tickets_router
from siem.router.active_defense import router as active_defense_router
from siem.router.ai import router as ai_router
from siem.router.automation import router as automation_router
from siem.router.campaigns import router as campaigns_router
from siem.router.incidents import router as incidents_router
from siem.router.monitoring import router as monitoring_router
from siem.router.reports import router as reports_router
from siem.router.threats import router as threats_router
from siem.router.waf import router as waf_router
from siem.router.course_cybersecurity import router as pyme_router
from siem.router.demo import router as demo_router
from siem.router.honeypot import router as honeypot_router
from siem.router.auth import router as auth_router
from siem.auth import SESSION_COOKIE, session_username


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

    # Fallo duro si producción arranca sin SIAM_API_KEY: sin esto, todo
    # /v1/* quedaría de nuevo sin autenticación (ver api_key_middleware más
    # abajo) -- exactamente el agujero encontrado el 2026-09-03.
    if settings_.ENVIRONMENT == "production" and not settings_.SIAM_API_KEY:
        raise RuntimeError(
            "SIAM_API_KEY no está configurada en producción -- todo /v1/* "
            "quedaría sin autenticación. Define SIAM_API_KEY en .env antes "
            "de arrancar."
        )

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

    # --- AUTENTICACIÓN DE /v1/* CON API KEY COMPARTIDA ---
    # Añadido 2026-09-03: se descubrió que todo /v1/* estaba expuesto sin
    # ninguna autenticación propia -- cualquiera que alcanzara el backend
    # (túnel, red local, o el fallo de puerto 8001 publicado en 0.0.0.0
    # corregido el mismo día en docker-compose.yml) tenía acceso completo a
    # incidentes y datos de cliente PYME, y podía hacer gastar las claves de
    # Anthropic/OpenAI/SMTP del backend llamando a /v1/ai/chat o
    # /v1/campaigns. Esta es una segunda capa independiente de Cloudflare
    # Access -- protege aunque Access esté mal configurado, aunque el puerto
    # se vuelva a exponer, o aunque la petición llegue desde dentro de la
    # LAN/red Docker.
    #
    # Excepción (encontrada 2026-09-03 al añadir la ruta de demo): los
    # enlaces de clic/reporte/confirmación de campañas (siem/router/
    # campaigns.py) están documentados como "sin autenticación a propósito"
    # porque van dentro de un email real a un empleado, que nunca puede
    # llevar la cabecera X-SIAM-API-Key -- pero al vivir bajo /v1/campaigns/
    # este middleware los bloqueaba igualmente con 401 en cuanto
    # SIAM_API_KEY estuviera configurada (como en producción), rompiendo el
    # simulacro de phishing sin que ningún test lo detectara (conftest.py
    # fuerza SIAM_API_KEY vacía). Se exime por patrón exacto, no por prefijo
    # /v1/campaigns/ entero, para no reabrir sin querer listar/analytics.
    _PUBLIC_CAMPAIGN_LINK = re.compile(
        r"^/v1/campaigns/[^/]+/(click|report)/[^/]+$"
        r"|^/v1/campaigns/[^/]+/targets/[^/]+/acknowledge$"
    )

    @app.middleware("http")
    async def api_key_middleware(request: Request, call_next):
        path = request.url.path
        # Una sesión de navegador válida (cookie firmada por la sesión de
        # administrador, ver siem/router/auth.py) también abre paso a /v1/*:
        # es la autenticación "humana" del dashboard real.
        session_user = session_username(
            request.cookies.get(SESSION_COOKIE), settings_.SIAM_AUTH_SESSION_SECRET
        )
        if (
            path.startswith("/v1/")
            and settings_.SIAM_API_KEY
            and not _PUBLIC_CAMPAIGN_LINK.match(path)
            and not session_user
        ):
            provided = request.headers.get("x-siam-api-key")
            if provided != settings_.SIAM_API_KEY:
                return JSONResponse({"detail": "No autorizado"}, status_code=401)
        return await call_next(request)
    # -------------------------------------------------------------

    # --- ACCESO AL DASHBOARD REAL (LOGIN + 2FA, 2026-09-08) ---
    # El dashboard de datos REALES (siem.db) queda detrás de /login con
    # usuario + contraseña (scrypt) + código 2FA TOTP (siem/router/auth.py),
    # como praxialabs.com/admin. La demo pública (/demo/*, siam_demo.db)
    # sigue SIN login a propósito: es un prospecto anónimo que debe poder
    # ver el SOC con datos inventados.
    #
    # Reglas:
    #   * Abierto siempre: /demo/*, /login, /logout, /health, /admin (panel
    #     señuelo de Active Defense) y los enlaces de campaña que viajan en
    #     emails reales (_PUBLIC_CAMPAIGN_LINK).
    #   * /v1/*: requiere sesión O la API key compartida. Si ninguna de las
    #     dos está configurada (desarrollo local puro), pasa -- mismo
    #     fail-open que en api_key_middleware.
    #   * "/" y "/dashboard": redirigen a /login si no hay sesión. Si no hay
    #     credenciales de admin configuradas (dev sin login), se sirven tal
    #     cual, como siempre.
    #   * El resto (/docs, /redoc, favicon, rutas inexistentes...) pasa:
    #     docs ya se desactiva en producción y no merece sesión en dev.
    @app.middleware("http")
    async def real_dashboard_auth_middleware(request: Request, call_next):
        path = request.url.path
        is_demo = path == "/demo" or path.startswith("/demo/")
        # El login solo se activa con los 4 valores presentes (como genera
        # siem/setup_auth.py). Configuración parcial = development sin login,
        # nunca un bloqueo por una variable a medio poner.
        auth_enabled = all((
            settings_.SIAM_ADMIN_USERNAME,
            settings_.SIAM_ADMIN_PASSWORD_HASH,
            settings_.SIAM_ADMIN_TOTP_SECRET,
            settings_.SIAM_AUTH_SESSION_SECRET,
        ))
        public = (
            path in {"/login", "/logout", "/health", "/admin"}
            or path.startswith("/admin/")
            or bool(_PUBLIC_CAMPAIGN_LINK.match(path))
        )
        session_user = session_username(
            request.cookies.get(SESSION_COOKIE), settings_.SIAM_AUTH_SESSION_SECRET
        )
        if is_demo or public or session_user:
            return await call_next(request)

        if path.startswith("/v1/"):
            auth_configured = bool(settings_.SIAM_API_KEY or auth_enabled)
            key_present = bool(
                settings_.SIAM_API_KEY
                and request.headers.get("x-siam-api-key") == settings_.SIAM_API_KEY
            )
            if not auth_configured or key_present:
                return await call_next(request)
            return JSONResponse({"detail": "Autenticación requerida"}, status_code=401)

        if path in {"/", "/dashboard"}:
            if not auth_enabled:
                return await call_next(request)
            return RedirectResponse("/login", status_code=303)

        return await call_next(request)
    # -------------------------------------------------------------

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

    # --- demosiem.praxialabs.com -> demo pública ---
    # Hostname del túnel Cloudflare pensado en su día para "demo con datos
    # reales, solo email de prospecto aprobado en Access" (ver docstring de
    # siem/router/demo.py) -- pero esa política de Access nunca se configuró:
    # descubierto 2026-09-04, servía el dashboard real sin gate (aunque
    # /v1/* seguía pidiendo X-SIAM-API-Key, así que no llegaba a filtrar
    # datos). Con /demo/dashboard ya cubriendo la demo pública, se reutiliza
    # el hostname redirigiendo todo su tráfico ahí -- así no hace falta
    # tocar la config de Cloudflare (el túnel ya entrega ese tráfico aquí).
    # Middleware añadido el último para que quede como capa más externa y
    # corte la petición antes de api_key_middleware/routing.
    @app.middleware("http")
    async def demo_host_redirect_middleware(request: Request, call_next):
        host = request.headers.get("host", "").split(":")[0].lower()
        if host == "demosiem.praxialabs.com":
            return RedirectResponse("https://siem.praxialabs.com/demo/dashboard", status_code=302)
        return await call_next(request)
    # -------------------------------------------------------------

    app.include_router(tickets_router)  # /v1/ingest/jira, /v1/metrics, /v1/tickets (SQLite, ya existía)
    app.include_router(monitoring_router)  # /v1/monitoring/* (módulo 1)
    app.include_router(incidents_router)  # /v1/incidents/* (módulo 3 y 4)
    app.include_router(ai_router)  # /v1/ai/chat (módulo 9)
    app.include_router(automation_router)  # /v1/automation/* (módulo 6)
    app.include_router(reports_router)  # /v1/reports/* (módulos 7 y 8)
    app.include_router(campaigns_router)  # /v1/campaigns/* (campañas de concienciación)
    app.include_router(threats_router)  # /v1/threats/* (catálogo de 30 amenazas + detección)
    app.include_router(waf_router)  # /v1/ingest/waf (WAAP hibrido: Cloudflare + Coraza)
    app.include_router(active_defense_router)  # /v1/active-defense/* (módulo premium, ver active_defense.py)
    app.include_router(pyme_router)  # /v1/pyme/* (Ciberseguridad PYME)
    app.include_router(demo_router)  # /demo, /demo/request (fuera de /v1/, público a propósito)
    app.include_router(honeypot_router)  # /admin -- panel señuelo de Active Defense (fuera de /v1/, público a propósito)
    app.include_router(auth_router)

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
