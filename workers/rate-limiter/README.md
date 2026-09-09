# RATE_LIMIT del Response Engine — Worker de Cloudflare

Ejecuta de verdad la acción `RATE_LIMIT` de Praxia Active Defense
(`siem/active_defense.py`) sin necesitar plan Cloudflare Business+.

## Por qué un Worker y no una regla nativa

La regla de rate limiting nativa de Cloudflare (Rulesets, fase
`http_ratelimit`) solo permite filtrar su `expression` por `Path` o
`Verified Bot` en los planes Free/Pro — `ip.src` no está permitido ahí
(error `not entitled ... an higher Advanced Rate Limiting plan is
required`). Sin filtrar por IP no hay forma de limitar solo a los
atacantes que marca el SOC.

El **Rate Limiting API de Workers** es un producto distinto (un binding en
tiempo de ejecución, no una regla de Rulesets) sin esa restricción de
plan. Este Worker:

1. Por cada petición, mira si la IP del cliente está en la lista que
   sincroniza SIAM (`siem/cloudflare_firewall.py::sync_rate_limit_rule`,
   vía Workers KV).
2. Si lo está, aplica el binding `RATE_LIMITER` y devuelve `429` si se
   supera el umbral.
3. Si no lo está (la inmensa mayoría del tráfico), pasa directo al origen
   sin gastar cupo del binding.

El umbral (peticiones/ventana) es **estático**, vive en `wrangler.toml` —
el binding no se puede reconfigurar en caliente vía API. Lo único
dinámico es *qué IPs* están sujetas a él, y eso lo controla SIAM.

## Requisitos

- Cuenta de Cloudflare con la zona ya proxied (naranja) — la misma que usa
  el resto del WAAP (`CLOUDFLARE_ZONE_ID`).
- Plan Workers **Free o Paid** ($5/mes). No hace falta WAF Business+.
- Wrangler >= 4.36.0 (`npm install -g wrangler` o `npx wrangler --version`).

## Despliegue

```bash
cd workers/rate-limiter
npx wrangler login

# 1. Crea el namespace KV (a nivel de CUENTA, no de zona)
npx wrangler kv namespace create RATE_LIMITED_IPS
# -> copia el "id" que imprime en wrangler.toml, campo kv_namespaces.id

# 2. Edita wrangler.toml:
#    - routes: pon el dominio/zona real (debe cubrir toda la zona)
#    - unsafe.bindings.simple: ajusta limit/period si 20 req/60s no encaja

# 3. Despliega
npx wrangler deploy
```

## Configura SIAM para usarlo

En el `.env` de SIAM (ver `.env.example`):

```bash
CLOUDFLARE_API_TOKEN=...      # ya lo tienes si BLOCK/CHALLENGE funcionan
CLOUDFLARE_ZONE_ID=...        # idem
CLOUDFLARE_ACCOUNT_ID=...     # nuevo -- Dashboard de Cloudflare, barra lateral derecha
CLOUDFLARE_RATE_LIMIT_KV_NAMESPACE_ID=...  # el "id" del paso 1 de arriba
```

El token necesita además el permiso **"Account > Workers KV Storage >
Edit"** (además de los que ya usan BLOCK/CHALLENGE/HONEYPOT).

Sin `CLOUDFLARE_ACCOUNT_ID`/`CLOUDFLARE_RATE_LIMIT_KV_NAMESPACE_ID`,
`RATE_LIMIT` se queda simulado igual que hasta ahora — desplegar este
Worker es opcional, no rompe nada de lo que ya funciona
(`is_rate_limit_configured` en `siem/cloudflare_firewall.py`).

## Verificar que funciona

```bash
# Confirma un RATE_LIMIT real desde el SOC (requiere PRAXIA_ACTIVE_DEFENSE_ENABLED)
curl -X POST "$SIAM_URL/v1/active-defense/respond?ip=203.0.113.9&action=RATE_LIMIT&confirm=true" \
  -H "X-SIAM-API-Key: $SIAM_API_KEY"
# -> "real": true, "resultado" menciona "regla compartida"

# Comprueba el valor en KV directamente
npx wrangler kv key get "rate-limited-ips" --namespace-id=<el id de arriba>
# -> {"ips":["203.0.113.9"]}

# Desde esa IP, más de `limit` peticiones en la ventana configurada
# deben empezar a devolver 429 Too Many Requests.
```

## Límites conocidos

- El rate limit se aplica **por colocación de Cloudflare** (datacenter),
  no de forma perfectamente global — un atacante distribuido en varias
  regiones puede esquivarlo parcialmente. Igual de válido para el caso de
  uso (mitigar fuerza bruta/scraping desde una IP concreta), pero no es
  un rate limit global exacto.
- La lista de IPs se actualiza con la latencia de propagación de Workers
  KV (normalmente segundos, con el `cacheTtl` de 60s del Worker puede
  tardar hasta un minuto en verse el cambio).
