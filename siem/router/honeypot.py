"""Página señuelo (honeypot) de Praxia Active Defense.

Cuando se confirma la acción HONEYPOT sobre una IP en `/v1/active-defense/
respond`, el conector real (ver `siem/cloudflare_firewall.py::sync_honeypot_
rule`) crea una Redirect Rule en Cloudflare que manda esa IP aquí en vez de
al sitio real -- el atacante sigue "dentro", pero no toca nada de verdad.

Fuera de /v1/* A PROPÓSITO (mismo criterio que siem/router/demo.py): tiene
que ser accesible SIN X-SIAM-API-Key, porque el visitante es por definición
alguien a quien nunca le vamos a poder pedir esa cabecera. Se sirve bajo
/admin porque encaja con la careta PHP/Apache de masquerade_headers_
middleware (siem/main.py) -- un panel de administración "viejo" es el cebo
más creíble dado ese fingerprint falso, y es justo el tipo de ruta que
cualquier scanner automatizado prueba a ciegas sin que haga falta que nadie
la enlace desde el sitio real.

Cada visita/intento se registra como Event(source="honeypot") por el mismo
pipeline que ya usa siem/router/waf.py (correlate_event -> threat_detection
-> killchain), así que un atacante que interactúa con el señuelo entra
directamente en Monitorización/Incidentes/Kill-chain como cualquier otra
señal -- no hace falta un dashboard aparte para esto.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse

from siem.correlation import correlate_event
from siem.models import Event, Severity
from siem.store import SiemStore, get_store

router = APIRouter(tags=["honeypot"])

# Ruta señuelo -- también la usa siem/cloudflare_firewall.py para construir
# la Redirect Rule real, así que si algún día cambia el path solo hay que
# tocarlo aquí.
HONEYPOT_PATH = "/admin"

_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Panel de Administración</title>
<style>
  body {{ font-family: Verdana, Arial, sans-serif; background: #e8e8e8; margin: 0;
         display: flex; align-items: center; justify-content: center; height: 100vh; }}
  .box {{ background: #fff; border: 1px solid #999; border-radius: 3px; padding: 28px 34px;
          width: 300px; box-shadow: 0 1px 3px rgba(0,0,0,.2); }}
  h1 {{ font-size: 15px; color: #333; margin: 0 0 4px; }}
  .sub {{ font-size: 11px; color: #888; margin: 0 0 18px; }}
  label {{ display: block; font-size: 12px; color: #555; margin: 10px 0 3px; }}
  input {{ width: 100%; box-sizing: border-box; padding: 6px 8px; font-size: 13px;
           border: 1px solid #bbb; border-radius: 2px; }}
  button {{ margin-top: 18px; width: 100%; padding: 7px; background: #4a6fa5; color: #fff;
            border: none; border-radius: 2px; font-size: 13px; cursor: pointer; }}
  .err {{ color: #b3261e; font-size: 12px; margin-top: 12px; }}
</style></head>
<body>
  <div class="box">
    <h1>Base de Datos de Clientes</h1>
    <p class="sub">Acceso restringido — solo personal autorizado</p>
    <form method="post" action="{path}">
      <label>Usuario</label>
      <input type="text" name="usuario" autocomplete="off">
      <label>Contraseña</label>
      <input type="password" name="password" autocomplete="off">
      <button type="submit">Entrar</button>
    </form>
    {error}
  </div>
</body></html>"""


def _client_ip(request: Request) -> str:
    # CF-Connecting-IP: el tráfico real siempre pasa por el túnel de
    # Cloudflare (ver docs/ARQUITECTURA.md) -- request.client.host solo
    # sirve de fallback en local/tests, donde sería 127.0.0.1/testclient.
    return request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "desconocida")


def _log(request: Request, store: SiemStore, *, severity: Severity, summary: str, usuario: str | None = None, password: str | None = None) -> None:
    ip = _client_ip(request)
    event = Event(
        source="honeypot",
        event_type="honeypot.login_attempt" if usuario is not None else "honeypot.view",
        severity=severity,
        summary=f"{summary} desde {ip}",
        description="Interacción con el panel señuelo de Active Defense -- ninguna credencial es real.",
        raw_payload={
            "client_ip": ip,
            "path": HONEYPOT_PATH,
            "user_agent": request.headers.get("user-agent", ""),
            "usuario_probado": usuario,
            "password_probada": password,
        },
    )
    incident = correlate_event(store, event)
    store.add_event(event)
    return incident


@router.get(HONEYPOT_PATH, response_class=HTMLResponse)
def honeypot_page(request: Request, store: SiemStore = Depends(get_store)) -> str:
    _log(request, store, severity=Severity.HIGH, summary="Visita al panel señuelo")
    return _PAGE.format(path=HONEYPOT_PATH, error="")


@router.post(HONEYPOT_PATH, response_class=HTMLResponse)
def honeypot_login_attempt(
    request: Request,
    usuario: str = Form(""),
    password: str = Form(""),
    store: SiemStore = Depends(get_store),
) -> str:
    # CRITICAL, no HIGH: probar credenciales es intención activa, no solo
    # curiosidad de un scanner automatizado que solo pide la página.
    _log(
        request, store, severity=Severity.CRITICAL,
        summary="Intento de login en el panel señuelo",
        usuario=usuario, password=password,
    )
    error = '<p class="err">Usuario o contraseña incorrectos.</p>'
    return _PAGE.format(path=HONEYPOT_PATH, error=error)
