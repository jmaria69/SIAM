# SIEM Security — SOC virtual con IA para pymes

## Descripción

**SIEM** (antes llamado "SIAM" — corregido el 2026-07-05, ver `CLAUDE.md`, incluido el rename del paquete Python `siam/` -> `siem/`) empezó como un backend de ingesta y métricas de tickets de Jira y se está ampliando a un **SOC (Security Operations Center) virtual con IA** para pymes, en fase MVP. Usa **FastAPI**. Proporciona:

- Ingesta de tickets desde Jira (persistidos en SQLite) y de eventos genéricos de seguridad (en memoria, ver `docs/ARQUITECTURA.md`).
- Correlación automática de eventos en incidentes por activo afectado.
- Motor de IA plegable (Claude / OpenAI / LLM local / reglas sin IA) para explicar alertas, chatear y generar informes.
- Gestión de incidentes, automatización con confirmación explícita, informes y panel ejecutivo.
- Dashboard, panel de incidentes, chat de IA y panel ejecutivo en React (`src/components/`).

El documento completo de arquitectura, alcance del MVP y roadmap está en `docs/ARQUITECTURA.md`. Las decisiones de diseño y su historial están en `CLAUDE.md`.

## Requisitos

- Python 3.9+
- Docker (opcional)
- Una API key de Anthropic u OpenAI si quieres el motor de IA con un modelo real (opcional — funciona sin ninguna, ver `AI_PROVIDER` más abajo)

## Instalación local

```bash
# Crear entorno virtual
python -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Copiar variables de entorno y ajustar AI_PROVIDER si quieres IA real
cp .env.example .env
```

## Ejecutar el servidor

```bash
uvicorn siem.main:app --host 0.0.0.0 --port 8001
```

Nota: el archivo de base de datos se sigue llamando `siam.db` a propósito (decisión de José, 2026-07-05) — solo se renombró el paquete Python, no el `.db`. No hace falta ningún `mv`/`cp` manual.

El backend estará disponible en `http://localhost:8001`.

## Docker

Construir la imagen:

```bash
docker build -t siem-backend .
```

Ejecutar con Docker Compose (exponiendo el puerto 8001):

```bash
docker compose up --build
```

## Tests

```bash
pytest tests/
```

`tests/test_api.py` usa una base SQLite en memoria (no toca `siem.db`). `tests/test_incidents.py` cubre ingesta genérica, correlación, incidentes, chat de IA y automatización sobre el store en memoria.

## Motor de IA

Configurable vía `.env` (`AI_PROVIDER=anthropic|openai|local|none`). Sin API key configurada, el sistema responde con explicaciones basadas en reglas — no bloquea el uso del resto del producto. Ver `siem/ai/providers.py`.

## Ver el SOC en el navegador

`http://localhost:8001/dashboard` — página autocontenida (React vía CDN, sin build) con Monitorización, Incidentes, Chat IA y Panel ejecutivo en pestañas. El widget viejo de tickets Jira sigue en `http://localhost:8001/`, sin tocar. Para incrustar los componentes en una app React/Next real, usa los `.jsx` de `src/components/`.

## Acceso al panel real (login + 2FA)

Desde el 2026-09-08, el dashboard de datos **reales** (`/`, siem.db) queda detrás
de un login de administrador con dos factores, misma idea que
`praxialabs.com/admin`:

1. **Usuario + contraseña** (hash scrypt, nunca en texto plano).
2. **Código TOTP 2FA** de tu aplicación de autenticación (Google Authenticator,
   Aegis, 1Password...).

Configuración (`.env` local o `.env.production` en el despliegue real):

```bash
python -m siem.setup_auth
```

La utilidad pide la contraseña (no la imprime), genera el hash, el secreto TOTP
con su URI `otpauth` para la app de autenticación, el secreto de sesión, e
imprime el bloque de variables listas para pegar:

```
SIAM_ADMIN_USERNAME=...
SIAM_ADMIN_PASSWORD_HASH=scrypt$...
SIAM_ADMIN_TOTP_SECRET=...
SIAM_AUTH_SESSION_SECRET=...
```

Comportamiento:

- **Con** `SIAM_ADMIN_*` configuradas: `GET /` sin sesión redirige a
  `/login`; `/v1/*` sin sesión ni API key devuelve 401. La cookie de sesión
  dura 8 h (`HttpOnly`, `SameSite=Lax`, `Secure` en producción).
- **Sin** credenciales configuradas (desarrollo local puro): el dashboard se
  sirve sin login, como siempre.
- La demo pública `/demo/dashboard` (base de datos `siam_demo.db`, datos
  inventados) **sigue sin login a propósito** — es un prospecto anónimo.
- El panel señuelo `/admin` (Active Defense honeypot) también permanece
  público a propósito.
- Si quieres regenerar el secreto 2FA (dispositivo perdido), vuelve a ejecutar
  `python -m siem.setup_auth` y sustituye los valores en el `.env`.

## API completa

Con el servidor arrancado: `http://localhost:8001/docs` (Swagger) o `/redoc`.

**En producción**, pon `ENVIRONMENT=production` en el `.env` del servidor real: `/docs`, `/redoc` y `/openapi.json` se desactivan por completo (404, no un simple ocultamiento). Con `ENVIRONMENT=development` (default) se quedan activos, como hasta ahora. Ver `siem/main.py::create_app` y `siem/config.py`.

## Seguridad — acción pendiente

`simulate_crisis.py` tenía un token de bot de Telegram hardcodeado y expuesto en el repo. Ya se movió a `.env`, pero **el token antiguo sigue siendo válido hasta que se revoque manualmente en BotFather**.

## Documentación adicional

- `docs/ARQUITECTURA.md`: arquitectura técnica, modelo de datos, alcance del MVP vs. visión completa, roadmap de escalabilidad.
- `CLAUDE.md`: notas y decisiones de diseño.
