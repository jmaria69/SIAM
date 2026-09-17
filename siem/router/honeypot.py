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

Señuelo en profundidad (2026-09-10): la regla de Cloudflare redirige A
CUALQUIER request de la IP honeypoteada a `/admin` (sin condición de path),
así que el atacante vive en una "cuenca": navegar a /admin/phpmyadmin le
rebotaría de vuelta aquí. Por eso la profundidad es CLIENT-SIDE: tras un
login fallido, JavaScript revela módulos falsos (phpMyAdmin, config.zip,
logs, consola de subida) y cada interacción manda un *beacon* POST al mismo
`/admin` con `step` y `elapsed_ms` (timer JS) -- para Cloudflare sigue
siendo una sola URL, y el SOC reconstruye el recorrido y el tiempo real que
el atacante pasó dentro. Un visitante sin JS (curl, scanners) sigue cayendo
solo en el evento de login, como siempre.

Cada visita/intento se registra como Event(source="honeypot") por el mismo
pipeline que ya usa siem/router/waf.py (correlate_event -> threat_detection
-> killchain), así que un atacante que interactúa con el señuelo entra
directamente en Monitorización/Incidentes/Kill-chain como cualquier otra
señal -- no hace falta un dashboard aparte para esto.

Este mismo router sirve también el panel de análisis del SOC bajo /v1/
(/v1/honeypot/sessions): aunque viva en el mismo fichero, ese lado SÍ pasa
por api_key_middleware/sesión como el resto del módulo, porque lo consume
el dashboard real, no el atacante.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Form, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from siem.correlation import correlate_event
from siem.honeypot_sessions import SESSION_EVENT_TYPES, build_sessions, session_stats
from siem.models import Event, Severity
from siem.store import SiemStore, get_store

router = APIRouter(tags=["honeypot"])

# Ruta señuelo -- también la usa siem/cloudflare_firewall.py para construir
# la Redirect Rule real, así que si algún día cambia el path solo hay que
# tocarlo aquí.
HONEYPOT_PATH = "/admin"

# Cookie de visita: agrupa todos los eventos de UNA visita del señuelo en una
# sesión (ver siem/honeypot_sessions.py::build_sessions). Fuera de /v1 a
# propósito; el atacante la recibe y la devuelve sin pedirle nada.
SESSION_COOKIE = "hp_sid"

def _to_int(value: str | None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>Panel de Administración</title>
<style>
  body { font-family: Verdana, Arial, sans-serif; background: #e8e8e8; margin: 0;
         display: flex; align-items: center; justify-content: center; height: 100vh; }
  .box { background: #fff; border: 1px solid #999; border-radius: 3px; padding: 28px 34px;
          width: 340px; box-shadow: 0 1px 3px rgba(0,0,0,.2); }
  h1 { font-size: 15px; color: #333; margin: 0 0 4px; }
  .sub { font-size: 11px; color: #888; margin: 0 0 18px; }
  label { display: block; font-size: 12px; color: #555; margin: 10px 0 3px; }
  input { width: 100%; box-sizing: border-box; padding: 6px 8px; font-size: 13px;
           border: 1px solid #bbb; border-radius: 2px; }
  button { margin-top: 18px; width: 100%; padding: 7px; background: #4a6fa5; color: #fff;
            border: none; border-radius: 2px; font-size: 13px; cursor: pointer; }
  .err { color: #b3261e; font-size: 12px; margin-top: 12px; display: none; }
  .panel { margin-top: 20px; border-top: 1px dashed #ccc; padding-top: 14px; display: none; }
  .panel h2 { font-size: 13px; color: #333; margin: 0 0 8px; }
  .mod { display: block; width: 100%; text-align: left; margin: 4px 0; padding: 7px 10px;
          font-size: 12px; background: #f2f4f7; border: 1px solid #d3d7de; border-radius: 3px;
          cursor: pointer; color: #333; }
  .mod:hover { background: #e6ebf2; }
  .res { display: none; margin-top: 8px; font-size: 11px; color: #444;
          border: 1px solid #dfe3e9; background: #fafbfc; padding: 8px 10px;
          white-space: pre-wrap; font-family: 'Courier New', monospace; }
  .warn { font-size: 11px; color: #8a6d3b; background: #fcf8e3; border: 1px solid #faebcc;
          padding: 6px 8px; margin-top: 12px; display: none; }
</style></head>
<body>
  <div class="box" id="box">
    <h1>Base de Datos de Clientes</h1>
    <p class="sub">Acceso restringido — solo personal autorizado</p>
    <form id="loginForm" method="post" action="__PATH__">
      <label>Usuario</label>
      <input type="text" name="usuario" id="usuario" autocomplete="off">
      <label>Contraseña</label>
      <input type="password" name="password" id="password" autocomplete="off">
      <button type="submit">Entrar</button>
    </form>
    <p class="err" id="loginError">Usuario o contraseña incorrectos.</p>
    <div class="panel" id="panel">
      <h2>Mantenimiento  ·  sesión vencida</h2>
      <button class="mod" id="btn-phpmyadmin">Gestor de base de datos (phpMyAdmin)</button>
      <div class="res" id="res-phpmyadmin">[db: clientes]  tabla: usuarios  (127 filas)
-----------------------------------------------------------
 id | usuario        | rol        | ultima_conexion
----+----------------+------------+------------------
  1 | jroot          | superadmin | 2026-09-09 18:04:22
  2 | operador_2     | operador   | 2026-09-08 09:11:03
  3 | respaldo_bkp   | respaldo   | (nunca)</div>
      <button class="mod" id="btn-config">Copia de respaldo (config.zip)</button>
      <div class="res" id="res-config">config.zip  ·  1.842.211 bytes
sha256: 3f2a9cbb1e10d4e6f0a78b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5
nota: incluye credenciales cifradas del entorno de producción (2026).</div>
      <button class="mod" id="btn-logs">Registro de actividad (logs)</button>
      <div class="res" id="res-logs">[2026-09-10 03:42:11] login OK  usuario=root  from=10.0.4.12
[2026-09-10 03:42:19] cambio de password solicitado  user=root
[2026-09-10 03:42:31] export masivo de la tabla clientes (850 filas)
[2026-09-10 03:42:44] entrada al panel de respaldo (nivel 2)</div>
      <button class="mod" id="btn-upload">Actualizar fichero (upload)</button>
      <div class="res" id="res-upload">consola de subida activa.
Drag & drop un fichero .php/.zip para sustituir el tema en /var/www/htdocs/
(Owner: root — sin validación de cabeceras en esta version).</div>
    </div>
    <p class="warn" id="limitWarn">Demasiados intentos. Espere 60 segundos o contacte con el administrador.</p>
  </div>
  <script>
    var PATH = '__PATH__';
    var t0 = performance.now();
    function beacon(step, extra) {
      var b = new URLSearchParams({step: step, elapsed_ms: String(Math.round(performance.now() - t0))});
      if (extra) { for (var k in extra) { if (extra[k]) b.set(k, extra[k]); } }
      fetch(PATH, {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: b.toString(), credentials: 'include'})
        .catch(function () {});
    }
    document.getElementById('loginForm').addEventListener('submit', function (e) {
      e.preventDefault();
      beacon('login', {usuario: document.getElementById('usuario').value, password: document.getElementById('password').value});
      document.getElementById('loginError').style.display = 'block';
      document.getElementById('panel').style.display = 'block';
    });
    var mods = {'phpmyadmin': 'btn-phpmyadmin', 'config': 'btn-config', 'logs': 'btn-logs', 'upload': 'btn-upload'};
    Object.keys(mods).forEach(function (step) {
      document.getElementById(mods[step]).addEventListener('click', function () {
        beacon(step);
        document.getElementById('res-' + step).style.display = 'block';
      });
    });
  </script>
</body></html>"""


def _client_ip(request: Request) -> str:
    # CF-Connecting-IP: el tráfico real siempre pasa por el túnel de
    # Cloudflare (ver docs/ARQUITECTURA.md) -- request.client.host solo
    # sirve de fallback en local/tests, donde sería 127.0.0.1/testclient.
    return request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "desconocida")


def _session_id(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def _log(
    request: Request,
    store: SiemStore,
    *,
    severity: Severity,
    summary: str,
    usuario: str | None = None,
    password: str | None = None,
    step: str | None = None,
    elapsed_ms: int | None = None,
    session_id: str | None = None,
) -> None:
    ip = _client_ip(request)
    # El evento de la PRIMERA vista no puede leer la cookie (se crea en esa
    # misma petición) -- por eso el handler GET genera el session_id antes y
    # lo pasa aquí explícitamente, para que ningún evento de la visita
    # quede huérfano fuera de su sesión.
    payload = {
        "client_ip": ip,
        "path": HONEYPOT_PATH,
        "user_agent": request.headers.get("user-agent", ""),
        "referer": request.headers.get("referer"),
        "accept_language": request.headers.get("accept-language"),
        "sec_ch_ua": request.headers.get("sec-ch-ua"),
        "session_id": session_id or _session_id(request),
    }
    event_type = "honeypot.view"
    if usuario is not None:
        event_type = "honeypot.login_attempt"
        payload["usuario_probado"] = usuario
        payload["password_probada"] = password
    if step is not None:
        event_type = "honeypot.step"
        payload["step"] = step
    if elapsed_ms is not None:
        payload["elapsed_ms"] = elapsed_ms
    event = Event(
        source="honeypot",
        event_type=event_type,
        # asset_id = IP atacante: sin esto, correlate_event (siem/
        # correlation.py) no tiene con qué agrupar y cada evento del señuelo
        # (vista, cada intento de login, cada beacon de paso) abría un
        # incidente nuevo y disparaba un email -- un atacante que probara
        # 123 credenciales generaba 123 incidentes y 123 correos. Con
        # asset_id=ip, todos los eventos de la misma IP dentro de la ventana
        # de correlación caen en el mismo incidente, y notificar_incidente
        # solo reavisa si la severidad escala (ver correlate_event).
        asset_id=ip,
        severity=severity,
        summary=f"{summary} desde {ip}",
        description="Interacción con el panel señuelo de Active Defense -- ninguna credencial es real.",
        raw_payload=payload,
    )
    correlate_event(store, event)
    store.add_event(event)


def _page() -> str:
    return _PAGE.replace("__PATH__", HONEYPOT_PATH)


@router.get(HONEYPOT_PATH, response_class=HTMLResponse)
def honeypot_page(request: Request, response: Response, store: SiemStore = Depends(get_store)) -> str:
    # Cookie de visita: una por explorador, agrupa todos los eventos de esta
    # visita en una sesión (ver siem/honeypot_sessions.py). Sin httponly=true
    # no: el JavaScript del señuelo la necesita. SameSite=Lax para que viaje
    # también en los beacons POST.
    sid = _session_id(request)
    if sid is None:
        # Cookie de visita nueva: esta petición la crea y YA viaja en el
        # evento de la vista, para que todo el recorrido quede en una sesión.
        sid = f"sis-{uuid.uuid4().hex[:12]}"
        response.set_cookie(
            SESSION_COOKIE, sid,
            max_age=7 * 24 * 3600, samesite="lax",
        )
    # LOW, no HIGH: pedir la página una vez y no volver es el patrón de
    # cualquier escáner automático de fondo (Shodan y similares) que prueba
    # /admin en medio internet -- no implica intención real. Escalamos a
    # MEDIUM en cuanto explora un paso del señuelo y a CRITICAL en cuanto
    # prueba una credencial (ver más abajo), que sí son señal de intención.
    _log(request, store, severity=Severity.LOW, summary="Visita al panel señuelo", session_id=sid)
    return _page()


@router.post(HONEYPOT_PATH, response_class=HTMLResponse)
def honeypot_post(
    request: Request,
    usuario: str = Form(""),
    password: str = Form(""),
    step: str = Form(""),
    elapsed_ms: str = Form(""),
    store: SiemStore = Depends(get_store),
) -> str:
    ms = _to_int(elapsed_ms)
    if step and step != "login":
        # Beacon de un paso del señuelo en profundidad (JS client-side).
        _log(
            request, store, severity=Severity.MEDIUM,
            summary=f"Paso '{step}' del señuelo en profundidad",
            step=step, elapsed_ms=ms,
        )
        # Respuesta mínima: el JavaScript no la lee, solo registra.
        return "<html><body><script>void 0;</script></body></html>"
    # CRITICAL, no HIGH: probar credenciales es intención activa, no solo
    # curiosidad de un scanner automatizado que solo pide la página.
    _log(
        request, store, severity=Severity.CRITICAL,
        summary="Intento de login en el panel señuelo",
        usuario=usuario, password=password, elapsed_ms=ms,
    )
    error = '<p class="err" id="loginError" style="display: block;">Usuario o contraseña incorrectos.</p>'
    return _PAGE.replace("__PATH__", HONEYPOT_PATH).replace(
        '<p class="err" id="loginError">Usuario o contraseña incorrectos.</p>', error
    )


# ---------------------------------------------------------------------------
# Panel de análisis del SOC -- /v1/honeypot/* (estos SÍ pasan por
# api_key_middleware/sesión, ver siem/main.py; los consume el dashboard real
# con datos REALES, y /demo/v1/* en la demo con la base de datos separada).
# ---------------------------------------------------------------------------
def _parse_date(value: str | None):
    if value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def sessions_payload(store: SiemStore, *, ip: str | None, date_from: str | None, date_to: str | None, limit: int) -> dict:
    events = store.list_honeypot_events(
        limit=limit,
        date_from=_parse_date(date_from),
        date_to=_parse_date(date_to),
    )
    # Solo los tipos que forman un recorrido (ver SESSION_EVENT_TYPES):
    # "honeypot.interaction" del dashboard de métricas no lleva session_id y
    # contaminaría el rollup agrupando por IP como falsas sesiones.
    events = [e for e in events if e.event_type in SESSION_EVENT_TYPES]
    if ip:
        events = [e for e in events if (e.raw_payload or {}).get("client_ip") == ip]
    sessions = build_sessions(events, limit=limit)
    # ioc_action expone el estado real de la IP (None/HONEYPOT/BLOCK/
    # RATE_LIMIT) para que el panel ofrezca la acción siguiente (ver
    # RESPONSE_ACTION_LABEL en soc_dashboard.html) sin tener que ir a la
    # pestaña Active Defense. "blocked" gatea el borrado (delete_sessions
    # más abajo): mientras la IP siga honeypoteada la sesión es intel
    # activa, solo se puede purgar una vez el analista la bloquea de
    # verdad (IOC action=BLOCK).
    ip_actions = {ioc.value: ioc.action for ioc in store.list_iocs() if ioc.type == "ip"}
    for session in sessions:
        action = ip_actions.get(session.get("ip"))
        session["ioc_action"] = action
        session["blocked"] = action == "BLOCK"
    # IPs puestas en HONEYPOT desde Active Defense (Atacantes) que TODAVÍA no
    # visitaron el señuelo -- la regla de Cloudflare ya las redirige, pero
    # hasta que no repitan tráfico no generan un Event(source="honeypot") y
    # por tanto no aparecen como sesión. Sin esto, el analista asigna
    # HONEYPOT en Atacantes y no ve ningún cambio en este panel hasta que el
    # atacante vuelva a conectar, lo que parece que la acción no hizo nada.
    session_ips = {s.get("ip") for s in sessions}
    pending_ips = sorted(ip for ip, action in ip_actions.items() if action == "HONEYPOT" and ip not in session_ips)
    if ip:
        pending_ips = [p for p in pending_ips if p == ip]
    return {"sessions": sessions, "stats": session_stats(sessions), "pending_ips": pending_ips}


@router.get("/v1/honeypot/sessions")
def honeypot_sessions(
    ip: Optional[str] = Query(None, description="Filtra sesiones de una IP de origen"),
    date_from: Optional[str] = Query(None, description="YYYY-MM-DD"),
    date_to: Optional[str] = Query(None, description="YYYY-MM-DD (inclusive)"),
    limit: int = Query(500, ge=1, le=5000),
    store: SiemStore = Depends(get_store),
) -> dict:
    """Sesiones del panel señuelo agrupadas por visita (cookie hp_sid o IP).

    Datos REALES de la base del SOC. Cada sesión trae el recorrido ordenado
    (events), las credenciales probadas, la duración y la profundidad máxima
    alcanzada en el señuelo en profundidad -- ver siem/honeypot_sessions.py.
    """
    return sessions_payload(store, ip=ip, date_from=date_from, date_to=date_to, limit=limit)


@router.get("/v1/honeypot/sessions/{session_id}")
def honeypot_session_detail(
    session_id: str,
    store: SiemStore = Depends(get_store),
) -> dict:
    """Una sesión concreta (journey completo). 404 si el id no coincide con
    ninguna sesión conocida (recuerda: sin cookie, los eventos agrupan por
    "ip:<client_ip>")."""
    payload = sessions_payload(store, ip=None, date_from=None, date_to=None, limit=5000)
    for session in payload["sessions"]:
        if session["session_id"] == session_id:
            return {"session": session}
    return JSONResponse({"detail": "Sesión no encontrada"}, status_code=404)


class DeleteSessionsRequest(BaseModel):
    session_ids: list[str]


def delete_sessions(store: SiemStore, session_ids: list[str]) -> dict:
    """Borra el journey completo de las sesiones indicadas -- solo si la IP
    de origen ya tiene un IOC action=BLOCK.

    Mientras una IP siga en HONEYPOT es el cebo activo con el que todavía se
    está "entrenando" (recogiendo credenciales/TTPs); borrar su journey antes
    de tiempo tira esa inteligencia. Una vez el analista decide bloquearla
    del todo, la sesión ya cumplió su propósito y es solo ruido acumulado --
    de ahí el filtro por `blocked` (ver sessions_payload) en vez de dejar
    borrar cualquier sesión a demanda.
    """
    payload = sessions_payload(store, ip=None, date_from=None, date_to=None, limit=5000)
    by_id = {s["session_id"]: s for s in payload["sessions"]}
    deleted: list[str] = []
    skipped: list[str] = []
    for session_id in session_ids:
        session = by_id.get(session_id)
        if session is None:
            continue
        if not session["blocked"]:
            skipped.append(session_id)
            continue
        store.delete_events_by_ids([e["id"] for e in session["events"]])
        deleted.append(session_id)
    return {"deleted": deleted, "skipped": skipped}


@router.delete("/v1/honeypot/sessions")
def delete_honeypot_sessions(
    payload: DeleteSessionsRequest,
    store: SiemStore = Depends(get_store),
) -> dict:
    """Borrado manual desde el panel del SOC (checkboxes en soc_dashboard.html).
    Devuelve qué session_ids se borraron y cuáles se saltaron por no estar
    bloqueadas -- el frontend ya filtra la selección, pero la API vuelve a
    comprobarlo por si el estado cambió entre carga y click."""
    return delete_sessions(store, payload.session_ids)