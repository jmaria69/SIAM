# Sesión de pruebas — 2026-07-02

## 1. Suite automatizada (`pytest`)

Ejecutado por José en su entorno (venv, WSL Ubuntu-22.04), no en esta sesión — el sandbox de comandos de esta sesión no tenía acceso funcional a la carpeta del proyecto.

```
platform linux -- Python 3.11.15, pytest-8.3.3, pluggy-1.6.0
rootdir: /home/jmari/proyectosIA/SIAM
configfile: pytest.ini
collected 13 items

tests/test_api.py::test_health                                          PASSED
tests/test_api.py::test_ingest_jira                                     PASSED
tests/test_api.py::test_metrics_initial                                 PASSED
tests/test_api.py::test_metrics_reflects_ingested_ticket                PASSED
tests/test_incidents.py::test_ingest_event_creates_incident             PASSED
tests/test_incidents.py::test_correlation_groups_same_asset_into_one_incident PASSED
tests/test_incidents.py::test_different_assets_create_different_incidents     PASSED
tests/test_incidents.py::test_overview_reports_open_alerts_and_risk     PASSED
tests/test_incidents.py::test_incident_status_update                    PASSED
tests/test_incidents.py::test_explain_incident_without_ai_key_falls_back_to_rules PASSED
tests/test_incidents.py::test_ai_chat_without_key_returns_fallback_not_error   PASSED
tests/test_incidents.py::test_automation_requires_confirmation          PASSED
tests/test_incidents.py::test_executive_panel_reflects_critical_incidents     PASSED

13 passed, 4 warnings in 0.46s
```

Confirmado en dos ejecuciones separadas (antes y después de añadir `GET /` → `soc_dashboard.html`), sin regresiones. Los 4 warnings son deprecaciones de Pydantic v1→v2 (`declarative_base()`, `.parse_obj()`, `.dict()`) en código preexistente — no afectan el resultado, pendiente de limpieza en fase 2.

## 2. Recorrido manual grabado (Game Bar, para edición en LinkedIn/Facebook)

Backend en `http://localhost:8001/`, navegador conectado vía Claude in Chrome, grabación de pantalla + audio con Xbox Game Bar (`Win+G`). Guion ejecutado:

1. **Monitorización** — estado inicial en 0 (riesgo 0/100, sin eventos). Se generan 4 eventos de prueba sobre el activo `web-prod-01`, uno por cada severidad (baja, media, alta, crítica).
   - Resultado: 1 alerta abierta, 4 eventos totales, riesgo global sube a 30/100.
2. **Incidentes** — los 4 eventos aparecen correlacionados en **un único incidente** (no cuatro sueltos), severidad escalada a "crítica" (la más alta de los eventos agrupados), score de riesgo 94/100, línea temporal con las 4 correlaciones registradas.
   - Se pulsa "Explicar con IA": responde el proveedor de reglas (`AI_PROVIDER=none` en este entorno) con un resumen del incidente y una recomendación genérica de contención.
3. **Chat IA** — pregunta "¿qué prioridad tiene el incidente crítico de web-prod-01?" con rol "Analista"; responde el mismo proveedor de reglas indicando cómo configurar un proveedor real (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `LOCAL_LLM_URL`).
4. **Ejecutivo** — refleja el mismo estado: riesgo 30, 1 incidente abierto, 1 crítico sin resolver, resumen en lenguaje no técnico y la amenaza principal listada.

Cada pantalla se comportó como se documentó en `docs/ARQUITECTURA.md` — sin errores de consola ni datos inconsistentes entre pestañas.

**Nota para la edición del vídeo**: todo el recorrido se hizo con `AI_PROVIDER=none`, así que las respuestas de IA que salen en la grabación son del proveedor de reglas (fallback), no de un LLM real. Si se quiere mostrar una respuesta generada de verdad para el vídeo final, hay que poner `ANTHROPIC_API_KEY` (o `OPENAI_API_KEY`/`LOCAL_LLM_URL`) en `.env`, reiniciar el servidor, y repetir el paso 2 o 3.

Clip guardado por Game Bar en `C:\Users\jmari\Videos\Captures\`.
