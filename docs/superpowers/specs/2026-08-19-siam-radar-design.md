# SIAM Radar — diseño

## Contexto

El usuario vio una captura de referencia ("Zexia Risk Monitor": mapa de riesgo económico/empresarial por territorio, con índice compuesto, factores, tendencia y confianza de IA) y quiso construir algo similar. Ya existe un proyecto hermano — **Praxia Radar** — que nació de esa misma captura y cubre riesgo *económico* (paro, tipos BCE, IPC) como lead magnet de marca praxialabs, no como producto de pago.

Este documento describe un producto **distinto y separado**: un radar de **riesgo cibernético** para SIAM (el SIEM/SOC de praxialabs), con dos objetivos:

1. Diferenciar SIAM frente a SIEMs genéricos (Wazuh/Graylog/Security Onion) añadiendo una capa que ningún competidor de ese segmento tiene: benchmarking de riesgo por sector/provincia + un forecast narrado, apoyado en el motor de kill-chain MITRE ATT&CK que SIAM ya tiene ([[siam-killchain-diferenciador]]).
2. Servir como superficie pública de marketing/lead-gen para atraer tráfico hacia SIAM, igual que Praxia Radar lo hace para la marca general.

**Hallazgo clave de la exploración del código actual (2026-08-19):** SIAM es **single-tenant** — una instalación Docker por cliente, sin ningún concepto de tenant/client_id en el modelo de datos (`siem/db_models.py`), y sin dato geográfico ni de sector de negocio en ningún sitio. El "efecto red" que motiva este proyecto no existe hoy; hay que construirlo desde cero, fuera del código actual de SIAM.

**Decisión de alcance (confirmada con el usuario):**
- Proyecto nuevo y separado de Praxia Radar (no un módulo dentro de él).
- Fuente de datos v1: **híbrida** — feeds públicos de amenazas (para no depender del volumen propio) + telemetría agregada y anonimizada de clientes SIAM que se apunten voluntariamente.
- Audiencia v1: **ambas superficies desde el inicio** — un mapa público (marketing) y un panel personalizado dentro del dashboard de cada cliente.
- El conector que agrega y empuja datos desde cada instalación SIAM vive en **su propio repo/servicio**, no como módulo dentro de `siem/`. El core de SIAM no se modifica salvo un añadido puramente de frontend (una pestaña nueva en `soc_dashboard.html`).

## Objetivo y no-objetivos

**Objetivo v1:** que exista el mecanismo de red completo (opt-in → agregación → scoring → dos superficies de lectura), sembrado con datos públicos para que no dependa de tener ya muchos clientes conectados, y que el índice de riesgo incluya una narrativa de "forecast" basada en el conocimiento MITRE ATT&CK ya codificado en SIAM.

**No-objetivos v1 (fuera de alcance, explícitamente):**
- Multi-tenencia real dentro de SIAM (el conector rodea el problema leyendo por API, no lo resuelve).
- Un modelo estadístico de forecast entrenado con datos propios — no hay volumen suficiente todavía; el forecast v1 es basado en conocimiento (reglas + estadísticas públicas), no en ML.
- Facturación o gating de pago del feature — se decide más adelante, no bloquea este diseño.
- Ampliar el módulo PYME (`siem/course_cybersecurity.py`) o su campo `sector` de texto libre — no es reutilizable como taxonomía (no persiste, es de un `PdsRequest` puntual) y no se toca en este proyecto.

## Arquitectura — 3 componentes nuevos

Ninguno de los tres modifica el backend de SIAM. El único cambio dentro del repo SIAM es una pestaña nueva de solo-frontend en `soc_dashboard.html`.

```
┌─────────────────────┐        push agregados         ┌──────────────────┐
│  radar-connector     │ ─────────(opt-in)────────────▶│   siam-radar      │
│  (1 por cliente que  │                                 │  (servicio        │
│   se apunte)          │◀──lee vía API existente────    │   central, repo   │
│                        │   GET /v1/incidents           │   hermano de SIAM)│
└─────────────────────┘   (de esa instancia SIAM)        └────────┬─────────┘
                                                                     │
                                            ┌────────────────────────┴───────────────┐
                                            │                                        │
                                    GET /v1/radar/map                 GET /v1/radar/client/{token}
                                    (público, sin auth)                 (autenticado por token)
                                            │                                        │
                                  ┌─────────▼─────────┐              ┌───────────────▼───────────────┐
                                  │  Página pública     │              │  Pestaña nueva en                │
                                  │  siam-radar (web)   │              │  soc_dashboard.html              │
                                  │  marketing/lead-gen │              │  "🛰️ Radar de Amenazas"          │
                                  └─────────────────────┘              └───────────────────────────────┘
```

Fuente adicional de `siam-radar`: job periódico de ingesta de **feeds públicos** (INCIBE-CERT avisos, y estadísticas sectoriales publicadas como ENISA/INCIBE informes anuales) para poblar el mapa desde el día 1, independientemente de cuántos clientes estén conectados.

### 1. `radar-connector`

- Repo/servicio nuevo, ligero (un solo script/servicio pequeño, sin necesidad de framework pesado — p. ej. un cron + un cliente HTTP).
- Configuración por instancia: URL + credencial de la SIAM del cliente, sector de negocio y provincia (nuevo dato — no existe en SIAM hoy, vive solo aquí), URL + token del servicio central `siam-radar`, flag de opt-in (por defecto `false`).
- Tarea periódica (p. ej. diaria): llama a `GET /v1/incidents` de esa instancia SIAM (endpoint ya existente, no se toca), agrega en memoria por táctica MITRE (usa la misma tabla de mapeo que `siem/threats_catalog.py` — se puede duplicar o referenciar como paquete, a decidir en el plan de implementación) y por severidad, en ventanas de 7 días.
- Envía SOLO el agregado (recuentos por táctica × severidad × sector × provincia del periodo) a `siam-radar` vía `POST /v1/radar/contribute`. Nunca IPs, nombres de activos, IDs de incidente ni texto libre.
- Endpoint/comando de "preview": antes de activar el opt-in, el operador puede ver exactamente el payload que se enviaría, sin enviarlo.

### 2. `siam-radar` (servicio central)

- Repo nuevo, hermano de SIAM (mismo patrón que `praxia-radar`).
- Persistencia propia (SQLite para empezar, consistente con cómo arrancó SIAM).
- Endpoints:
  - `POST /v1/radar/contribute` — recibe agregados de `radar-connector` instancias que hicieron opt-in.
  - `GET /v1/radar/map` — público, sin auth. Devuelve el índice por sector×provincia, tendencia, técnica dominante del periodo, y 2-3 líneas de "próximos riesgos a vigilar" (derivadas de los feeds públicos).
  - `GET /v1/radar/client/{token}` — autenticado con el token que `radar-connector` genera al activar opt-in. Devuelve el mismo índice más la comparación del cliente contra el agregado de su sector/provincia, y la narrativa de forecast personalizada.
- Motor de scoring: índice 0-100 por sector×provincia, combinando (a) señal pública (feeds) y (b) señal propia agregada de clientes conectados, con peso creciente hacia (b) según aumente el número de contribuyentes por celda sector×provincia (para evitar que una celda con 1 solo cliente domine el índice de esa celda — hay que fijar un mínimo de contribuyentes antes de que el peso propio supere al público; el número mínimo exacto y la fórmula de ponderación se definen en el plan de implementación, no en este diseño).
- Motor de forecast: capa basada en conocimiento, no en ML. Usa el orden de tácticas MITRE ATT&CK ya codificado en `killchain.py`/`threats_catalog.py` de SIAM (se referencia o se duplica esa tabla — a decidir en el plan) combinado con estadísticas publicadas (INCIBE/ENISA) sobre qué técnicas preceden a cuáles por sector, para generar frases tipo: *"en el sector logística, patrones de reconocimiento + acceso inicial preceden a incidentes de ransomware en el X% de los casos documentados (fuente: INCIBE informe Y)"*. Estas estadísticas públicas se cargan como datos de referencia versionados (no se scrapean en vivo), citando la fuente.

### 3. Dos superficies de lectura

- **Página pública `siam-radar` (web):** HTML autocontenido (mismo patrón "sin build" que usa SIAM y Praxia Radar), con la paleta de `marketing_linkedin_kit.html` (`--bg:#0a0f1a`, `--surface:#111927`, `--accent:#38bdf8`, semáforo `--good/--warn/--risk`). Mapa de España por provincia/sector — se puede reutilizar la técnica de cartograma hexagonal validada en Praxia Radar (evita SVG de fronteras reales, pesado) si encaja visualmente, a decidir al implementar. Consume solo `GET /v1/radar/map`.
- **Pestaña nueva en `soc_dashboard.html`** ("🛰️ Radar de Amenazas"), siguiendo el patrón visual/estructural de `PymeCybersecurityPanel` (línea ~1764) ya existente: un componente React más, con su propio `fetch` (try/catch, consistente con el resto del dashboard) directamente a `GET /v1/radar/client/{token}` de `siam-radar` — **no pasa por el backend de SIAM**. El token se configura como constante/config del dashboard (inyectado igual que otras claves de front, a definir en el plan). Muestra: score propio vs. agregado de su sector/provincia, tendencia, y la narrativa de forecast.

## Privacidad y consentimiento

No existe hoy ningún mandato de privacidad documentado en SIAM (se verificó — no hay ninguna declaración de "no enviar a terceros" en código ni docs), así que este diseño lo fija explícitamente como regla del propio proyecto:

- Opt-in **desactivado por defecto** en cada `radar-connector`.
- Solo se transmiten **agregados numéricos** (recuentos por táctica×severidad×sector×provincia); nunca IP, nombre de activo, ID de incidente, ni texto libre (descripción, evidencia, etc.).
- Comando/endpoint de "preview" obligatorio antes de poder activar el opt-in — el operador ve el payload exacto.
- El servicio central `siam-radar` no debe poder reconstruir un incidente individual a partir de lo que recibe — el test de "no-PII" (ver Testing) verifica esto.

## Testing y verificación

- Tests unitarios del motor de scoring de `siam-radar` con fixtures de agregados sintéticos (varias combinaciones sector×provincia, con y sin señal propia).
- Test de "no-PII" sobre `radar-connector`: dado un conjunto de incidentes con IPs/nombres de activo/texto libre, el payload generado por `POST /v1/radar/contribute` no debe contener ninguno de esos valores — test que falla explícitamente si aparece algo no esperado.
- Test de la fórmula de ponderación pública/propia en el motor de scoring (verificar que una celda con 1 solo contribuyente no domina el índice).
- Verificación manual end-to-end: levantar `siam-radar` + una instancia SIAM de demo + un `radar-connector` apuntando a ella, activar opt-in, confirmar que el agregado aparece reflejado en `GET /v1/radar/map` y en la pestaña nueva del dashboard.

## Riesgos y preguntas abiertas para el plan de implementación

- Fórmula exacta de ponderación público/propio y umbral mínimo de contribuyentes por celda — se define al implementar el motor de scoring, no aquí.
- Cómo se referencia la tabla de mapeo MITRE de `threats_catalog.py` desde `radar-connector`/`siam-radar` (¿paquete compartido, duplicación deliberada, o llamada a un endpoint de SIAM que la exponga?) — a decidir en el plan.
- Mecanismo de inyección del token/config en `soc_dashboard.html` para la nueva pestaña (hoy el dashboard no tiene ningún mecanismo de config de front más allá de las URLs de API relativas) — a decidir en el plan.
- Nombre de marca final del producto (aquí se usa "SIAM Radar" / `siam-radar` como nombre de trabajo) — pendiente de decisión del usuario, igual que se hizo con Praxia Radar.
