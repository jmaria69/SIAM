# SIEM Security — SOC virtual con IA para pymes

*(Nota 2026-07-05: el proyecto se llamaba internamente "SIAM" — corrección de nomenclatura a "SIEM" (Security Information and Event Management, el término real de la industria). Ver `CLAUDE.md` para el detalle del rename.)*

## Arquitectura documental del MVP (fase 1)

El prompt original pide un SOC empresarial completo (microservicios, Kubernetes, Zero Trust, cumplimiento normativo, panel ejecutivo, motor de IA con correlación de amenazas, automatización con aprobación humana...). Eso es un producto de varios meses de un equipo, no algo que se genera de una vez. Lo que se documenta y construye aquí es un **MVP real y ejecutable** que implementa el núcleo funcional de cada módulo sobre el código que ya existía en este repositorio, y deja una ruta de escalado explícita hacia la visión completa.

### Auditoría del estado real del repo (corregida)

La primera pasada de exploración usó una herramienta de listado de archivos que falló en silencio sobre esta ruta de red (`\\wsl.localhost\...`) — devolvía "no encontrado" incluso para módulos que sí existían. Eso llevó a un diagnóstico inicial incorrecto (se llegó a afirmar que `siam/main.py` no existía). Se corrigió leyendo cada archivo directamente. Estado real confirmado:

- `siam/main.py`, `siam/router/api.py`, `siam/database.py` y `siam/db_models.py` **sí existen y funcionan**: el backend ya persiste tickets en **SQLite** (no en memoria, como decía `CLAUDE.md` — ese documento estaba desactualizado respecto al código).
- `app.py` y `jira_to_siam_mapper.py` en la raíz del proyecto son una **versión antigua duplicada**, no la que usan Docker/README (`uvicorn siam.main:app`). No están rotos, están muertos y desincronizados (esa versión usa almacenamiento en memoria y un modelo ligeramente distinto). Se marcan como obsoletos en vez de borrarlos.
- **Bug real**: `docker-compose.yml` publica el puerto `8002:8002`, pero la app escucha en `8001` (`.env`, `Dockerfile` y `README` coinciden en 8001). El servicio queda inalcanzable vía `docker compose up`. Corregido.
- **Bug real**: `test_ingest.sh` apunta a `http://localhost:8000`, no a `8001`. Corregido.
- **Bug real**: `SiemCrmDashboard.jsx` (entonces `SiamCrmDashboard.jsx`) hacía `fetch('http://localhost:8000/v1/metrics')` — puerto equivocado (la app escucha en 8001). El dashboard nunca había podido cargar datos reales. Corregido.
- **Bug real**: `siam/main.py` no tenía CORS configurado, pese a que `CLAUDE.md` decía "CORS gestionado en main.py". Solo el `app.py` obsoleto de la raíz lo tenía. Corregido añadiendo `CORSMiddleware` al `main.py` real.
- **Bug real**: el modelo `SiemTicket` (entonces `SiamTicket`) no tiene los campos que el dashboard React (`SiemCrmDashboard.jsx`) espera leer (`external_id`, `provider`, `summary`) — esas columnas se renderizaban vacías. Corregido añadiendo esos campos derivados en la respuesta de `/v1/metrics`.
- **Bug real**: `tests/test_api.py` escribe contra el `siam.db` real (SQLite en disco) en vez de una base aislada. El primer test inserta un ticket con `ticket_id="TEST-123"`; en la segunda ejecución, esa misma fila ya existe y la inserción falla por restricción de unicidad. Además `test_metrics_initial` asume `total_tickets == 0`, lo cual deja de ser cierto en cuanto el archivo `siam.db` acumula datos de ejecuciones anteriores o de las demos (`simulate_crisis.py`, `test_ingest.sh`). Corregido con una base SQLite en memoria inyectada solo para tests (override de la dependencia `get_db`).
- **Hallazgo de seguridad real**: `simulate_crisis.py` tenía un token de bot de Telegram y un `chat_id` **en texto plano, commiteados al repo**. Es una credencial expuesta. Se movió a variables de entorno, pero **el token ya expuesto sigue siendo válido hasta que José lo revoque en BotFather** — eso no se puede hacer desde aquí, requiere acceso a su cuenta de Telegram.

## Alcance del MVP (fase 1) vs. visión completa

| Módulo del prompt original | Estado en el MVP | Pendiente para fases siguientes |
|---|---|---|
| 1. Centro de monitorización | `GET /v1/monitoring/overview` (KPIs, riesgo, tiempo real) + `GET /v1/monitoring/timeseries` (ataques por hora/día/mes/año, persistente en SQLite) | Backups automatizados de `siem.db` |
| 2. Motor de IA | Interfaz plegable (Claude / OpenAI / LLM local / reglas sin IA) que explica alertas y resume | Detección de anomalías por ML, fine-tuning con datos propios |
| 3. Gestión de incidentes | CRUD, timeline, evidencias, estados (abierto/investigación/resuelto) | Adjuntos binarios, SLA automatizados |
| 4. Correlación de eventos | Agrupación determinista por activo + ventana temporal | Correlación por grafo / cadenas de ataque multi-etapa |
| 5. Inteligencia de amenazas | Modelo `IOC` y endpoint de consulta | Feeds externos (MISP, OTX), enriquecimiento automático |
| 6. Automatización | Reglas con ejecución simulada que exige `confirm=true` explícito | Conectores reales (EDR, firewall, ticketing externo) |
| 7. Informes | Diario/semanal/mensual generados con IA sobre datos reales | Exportación PDF, envío programado por email |
| 8. Panel ejecutivo | Endpoint + componente React con resumen no técnico | Comparativas sectoriales, cumplimiento normativo detallado |
| 9. Chat de IA | `POST /v1/ai/chat` con contexto de incidente y rol de usuario | Memoria de conversación persistente, RAG sobre documentación del cliente |
| 10. Roles | Rol vía cabecera `X-User-Role` (stub), seis roles definidos | JWT + MFA + gestión de sesiones real |
| Seguridad (Zero Trust, MFA, cifrado, HA) | Documentado como diseño objetivo | Implementación real — requiere gestor de secretos, IdP |

## Arquitectura técnica (MVP)

```
                        ┌──────────────────────────┐
                        │   Frontend (React)        │
                        │  Monitorización /          │
                        │  Incidentes / Chat IA /    │
                        │  Panel ejecutivo           │
                        └────────────┬───────────────┘
                                     │ REST / JSON (fetch, polling)
                        ┌────────────▼───────────────┐
                        │      FastAPI (siem/)         │
                        │  siem/router/api.py (tickets)│
                        │  siem/router/monitoring.py   │
                        │  siem/router/incidents.py    │
                        │  siem/router/ai.py           │
                        │  siem/router/automation.py   │
                        │  siem/router/reports.py      │
                        └──────────────┬───────────────┘
                                       │
                        ┌──────────────▼───────────────┐
                        │  siem/store.py (SiemStore) —  │
                        │  SQLAlchemy sobre siem.db:     │
                        │  tickets, Asset, Event,        │
                        │  Incident, IOC, Automation-    │
                        │  Rule, Report. Un único motor. │
                        └──────────────┬───────────────┘
                                       │
                              ┌────────▼────────┐
                              │  AI provider      │
                              │  Claude / OpenAI / │
                              │  local / reglas    │
                              └────────────────────┘
```

Decisiones de esta fase:

- **Persistencia unificada en SQLite** (`siam/store.py`, respaldado por SQLAlchemy sobre `siam.db`). Hasta hace poco las entidades nuevas del SOC vivían en memoria (`InMemoryStore`) como simplificación deliberada del primer MVP; se consolidó en el mismo motor SQLite que ya usaban los tickets porque el simulador de crisis y las métricas por tiempo (hora/día/mes/año) no tienen sentido si se borran en cada reinicio. El patrón repositorio (`siam/store.py` expone los mismos métodos que antes: `add_incident`, `list_incidents`...) hizo que el swap no tocara ni un router.
- **Monolito modular, no microservicios todavía.** Un solo servicio FastAPI con routers separados por dominio dentro de `siem/router/`. El prompt pide microservicios/K8s desde el día uno; eso no es defendible para un MVP de una persona. Los routers ya dejan las costuras naturales para separar servicios cuando haga falta.
- **Motor de IA agnóstico al proveedor**, tal y como se pidió: `AI_PROVIDER=anthropic|openai|local|none` en `.env`. Sin ninguna API key configurada, el sistema sigue funcionando con explicaciones basadas en reglas — no bloquea la demo ni obliga a pagar por un LLM para probarlo.
- **Automatización con confirmación obligatoria.** Ninguna acción que toque sistemas del cliente se ejecuta sin `confirm=true` explícito — cumple el requisito de que la IA no sustituya el juicio humano en acciones críticas.

## Modelo de datos (resumen)

- **Asset**: `id, name, type, environment, criticality, owner, authorized`
- **Event**: `id, source, external_id, asset_id, event_type, severity, timestamp, raw_payload` — unidad mínima ingerida
- **Incident**: `id, title, severity, status, description, affected_assets[], event_ids[], timeline[], evidence[], recommendations[], risk_score, created_at`
- **IOC**: `id, type(ip/domain/hash), value, campaign, ttps[], confidence`
- **AutomationRule**: `id, trigger, action, requires_confirmation, enabled`
- **Report**: `id, type(daily/weekly/monthly), period_start, period_end, generated_at, content`
- **Role** (enum): `superadmin, admin, it_responsable, analista, auditor, direccion`
- **SiemTicket** (existente, SQLite; clase renombrada de `SiamTicket`): `ticket_id, status, service, description, priority`

Detalle exacto en `siem/models.py` y `siem/db_models.py`.

## API (MVP)

Documentación interactiva automática de FastAPI en `/docs` y `/redoc` — no se mantiene un spec manual aparte para que no se desincronice del código. Endpoints principales:

- `GET /health`
- `POST /v1/ingest/jira` · `GET /v1/metrics` · `GET /v1/tickets` (existentes, SQLite)
- `GET /v1/monitoring/overview` (incluye `eventos_ultimo_minuto`, "tiempo real") · `GET /v1/monitoring/timeseries?granularity=hour|day|month|year` · `POST /v1/monitoring/ingest` (eventos genéricos, no solo Jira)
- Simulador de crisis: `GET /v1/monitoring/scenarios` · `POST /v1/monitoring/simulate/{scenario_id}` (arranca en segundo plano, `asyncio.create_task`, delays reales entre eventos) · `GET /v1/monitoring/simulate/{run_id}/status` (polling). Ver `siem/scenarios.py` + `siem/simulator.py` — inyecta sobre el mismo `correlate_event`/`store.add_event` que `/v1/monitoring/ingest`, no es un camino aparte.
- `GET /v1/incidents` · `GET /v1/incidents/{id}` · `PATCH /v1/incidents/{id}` · `POST /v1/incidents/{id}/actions`
- `POST /v1/ai/chat` · `POST /v1/ai/explain/{incident_id}`
- `GET /v1/automation/rules` · `POST /v1/automation/rules` · `POST /v1/automation/rules/{id}/execute?confirm=true`
- `GET /v1/reports/{daily|weekly|monthly}` · `GET /v1/reports/executive`

## Plan de despliegue (MVP)

1. `docker compose up --build` levanta el backend en `:8001` (puerto corregido).
2. Frontend: los componentes `.jsx` en `src/components/` se incrustan en cualquier app React/Next existente; no se asume un proyecto Next.js propio porque no hay `package.json` en el repo.
3. Variables nuevas en `.env` (ver `.env.example`): `AI_PROVIDER`, `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `LOCAL_LLM_URL`, `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`.
4. **Acción pendiente de José, no automatizable desde aquí**: revocar el token de Telegram expuesto en BotFather y generar uno nuevo antes de desplegar en cualquier entorno compartido.

## Estrategia de escalabilidad (fases siguientes)

- **Fase 2**: migrar de SQLite a PostgreSQL cuando haya concurrencia real de varios clientes (SQLite con `StaticPool`/archivo único no escala a múltiples workers escribiendo a la vez); autenticación JWT + MFA real; feeds de threat intel externos.
- **Fase 3**: separar ingesta/correlación en un worker asíncrono (cola tipo Redis/RabbitMQ) para no bloquear la API con picos de eventos; multi-tenant real (hoy el modelo es single-tenant).
- **Fase 4**: contenedores por dominio (ingesta, IA, reporting) + orquestación K8s — solo cuando el volumen de eventos o el número de clientes lo justifique.

## Plan de mantenimiento

- `pytest tests/` debe pasar antes de cada cambio. Ahora usa una base SQLite en memoria inyectada solo para tests, aislada del `siem.db` real.
- Ningún secreto (tokens, API keys) va hardcodeado — todo pasa por `.env` (excluido en `.gitignore`).
- `app.py` y `jira_to_siam_mapper.py` (raíz) quedan marcados como obsoletos con un comentario explícito; no se borran para no destruir historial sin permiso explícito.

## Cumplimiento normativo (nota, no implementación)

Para pymes en España/UE esto implica como mínimo RGPD (base legal para procesar logs con datos personales, plazos de retención) y, según sector, ENS o NIS2. No se implementa en el MVP — queda anotado porque condiciona decisiones de fase 2 (dónde se aloja la base de datos, cifrado en reposo, registro de auditoría de quién accedió a qué incidente).

## Nota honesta sobre esta entrega

Esta sesión no tuvo acceso a una shell funcional contra esta carpeta (el sandbox de comandos falló por la misma ruta de red que rompió el listado de archivos), así que **el código no se pudo ejecutar ni testear en esta sesión**. Se escribió con cuidado y revisando manualmente cada import, pero José debe correr `pytest tests/` y `docker compose up --build` él mismo antes de confiar en que todo funciona a la primera. Comandos exactos a correr:

```bash
cd ~/proyectosIA/SIAM
source .venv/bin/activate   # o crear uno nuevo si no existe
pip install -r requirements.txt
pytest tests/ -v
uvicorn siem.main:app --host 0.0.0.0 --port 8001 --reload
# en otra terminal:
bash test_ingest.sh
```
