/**
 * Worker del RATE_LIMIT de Praxia Active Defense.
 *
 * Ver wrangler.toml para el porqué (Rulesets rate limiting no admite
 * filtrar por IP salvo en plan Business+; esto usa el Rate Limiting API de
 * Workers, un producto distinto sin esa restricción).
 *
 * Contrato con siem/cloudflare_firewall.py::sync_rate_limit_rule: el valor
 * de RATE_LIMITED_IPS (clave "rate-limited-ips") es un JSON de la forma
 * {"ips": ["1.2.3.4", ...]}. El límite/ventana NO viaja en el KV -- es el
 * binding RATE_LIMITER, fijo en wrangler.toml.
 */

interface RateLimiterBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  RATE_LIMITED_IPS: KVNamespace;
  RATE_LIMITER: RateLimiterBinding;
}

const KV_KEY = "rate-limited-ips";

interface RateLimitedIpsPayload {
  ips: string[];
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const ip = request.headers.get("CF-Connecting-IP");

    if (ip) {
      const limited = await isRateLimitedIp(ip, env);
      if (limited) {
        try {
          const { success } = await env.RATE_LIMITER.limit({ key: ip });
          if (!success) {
            return new Response("Too Many Requests", {
              status: 429,
              headers: { "Retry-After": "60" },
            });
          }
        } catch (err) {
          // Fallar ABIERTO, no cerrado -- mismo criterio que el resto de
          // SIAM (una integración opcional nunca debe tumbar el sitio real
          // del cliente). Un fallo del binding no debe convertirse en un
          // apagón; el peor caso es perder temporalmente el rate limit de
          // esta IP concreta, que ya está además marcada y visible en el
          // dashboard de Active Defense.
          console.error("RATE_LIMITER.limit() falló, se deja pasar la petición:", err);
        }
      }
    }

    // Passthrough al origen -- este Worker solo añade una comprobación
    // antes de reenviar, no sustituye el resto de la pila de Cloudflare.
    return fetch(request);
  },
};

async function isRateLimitedIp(ip: string, env: Env): Promise<boolean> {
  // cacheTtl reduce la lectura del KV a como mucho una vez cada 60s por
  // colocación de Cloudflare -- suficiente para esto (la lista cambia
  // cuando el SOC confirma una acción, no en tiempo real petición a
  // petición) y evita facturar una lectura de KV por cada request.
  const raw = await env.RATE_LIMITED_IPS.get(KV_KEY, { cacheTtl: 60 });
  if (!raw) return false;

  try {
    const payload = JSON.parse(raw) as RateLimitedIpsPayload;
    return Array.isArray(payload.ips) && payload.ips.includes(ip);
  } catch (err) {
    console.error("KV de rate limit con JSON inválido, se ignora:", err);
    return false;
  }
}
