"""Rollup de sesiones del honeypot (siem/router/honeypot.py).

Por qué existe: cada interacción con el panel señuelo se registra como un
Event(source="honeypot") independiente (siem/router/honeypot.py::_log) --
un atacante que cae en el señuelo y lo explora genera varios eventos sueltos
(vista, intento de login, beacon de cada paso del señuelo en profundidad).
Para reconstruir "cómo fue" (recorrido, credenciales probadas, cuánto tiempo
estuvo) hay que volver a unirlos.

El agrupador usa el `session_id` que la página señuelo inyecta como cookie
(`hp_sid`) y repite en cada evento. Los eventos viejos (o cualquiera sin
cookie) agrupan por client_ip como fallback -- peor granularidad, pero ese
evento sigue contando en su sesión "por IP".

A diferencia de attacker_aggregator (rollup PERSISTENTE e incremental por
IP, solo WAF_SOURCES), esto se calcula EN MEMORIA por petición sobre
source=="honeypot" ya filtrado por fecha en SQL -- el volumen de eventos
honeypot es pequeño (una página señuelo, no miles de IPs) y así el panel
puede re-agrupar con el journey completo sin mantener otro cursor. Si algún
día el señuelo escala a cientos de eventos, se migra al mismo patrón
incremental, pero hoy no lo justifica.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Sequence

from siem.models import Event, Severity

# Tipos de evento que constituyen un RECORRIDO dentro del señuelo. Excluye
# "honeypot.interaction": lo utiliza siem/store.py::attack_metrics como
# contador agregado del dashboard de métricas, sin session_id ni paso, y si
# entrara en el rollup agruparía por IP como sesiones sinuosas sin sentido.
SESSION_EVENT_TYPES: frozenset[str] = frozenset({
    "honeypot.view", "honeypot.login_attempt", "honeypot.step",
})

# Etiquetas humanas para cada tipo de evento del señuelo -- las usa el panel
# para pintar el journey sin inventar descripciones en el frontend.
STEP_LABELS: dict[str, str] = {
    "honeypot.view": "Vista del panel señuelo",
    "honeypot.login_attempt": "Intento de login",
    "honeypot.step:phpmyadmin": "Acceso a phpMyAdmin falso",
    "honeypot.step:config": "Descarga de config.zip falso",
    "honeypot.step:upload": "Consola de subida de archivos",
    "honeypot.step:logs": "Exploración de logs falsos",
    "honeypot.step": "Paso del señuelo en profundidad",
}

# Profundidad de cada paso -- la "distancia" dentro del señuelo. Ver
# siem/router/honeypot.py::_PAGE para el orden en que se revelan.
_STEP_DEPTH: dict[str, int] = {
    "honeypot.view": 1,
    "honeypot.step:phpmyadmin": 2,
    "honeypot.step:config": 2,
    "honeypot.step:logs": 2,
    "honeypot.step:upload": 3,
}


def _session_key(event: Event) -> str:
    sid = (event.raw_payload or {}).get("session_id")
    if sid:
        return str(sid)
    ip = (event.raw_payload or {}).get("client_ip") or "desconocida"
    return f"ip:{ip}"


def _event_dict(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "session_id": (event.raw_payload or {}).get("session_id"),
        "event_type": event.event_type,
        "severity": event.severity.value,
        "summary": event.summary,
        "timestamp": event.timestamp,
        "step": (event.raw_payload or {}).get("step"),
        "elapsed_ms": (event.raw_payload or {}).get("elapsed_ms"),
        "usuario_probado": (event.raw_payload or {}).get("usuario_probado"),
        "password_probada": (event.raw_payload or {}).get("password_probada"),
        "client_ip": (event.raw_payload or {}).get("client_ip"),
        "user_agent": (event.raw_payload or {}).get("user_agent"),
        "referer": (event.raw_payload or {}).get("referer"),
        "accept_language": (event.raw_payload or {}).get("accept_language"),
    }


def build_sessions(events: Sequence[Event], limit: int = 500) -> list[dict]:
    """Agrupa eventos honeypot (entregados en orden ASC) en sesiones.

    Una sesión = una visita del señuelo (mismo session_id), o fallback por
    IP para eventos sin cookie. Por sesión se devuelve el recorrido ordenado
    (events), las credenciales probadas, la duración (first/last timestamp)
    y la profundidad máxima alcanzada en el señuelo en profundidad.
    """
    order = {s.value: i for i, s in enumerate(Severity)}
    sessions: dict[str, dict[str, Any]] = {}

    for event in events:
        key = _session_key(event)
        sess = sessions.get(key)
        if sess is None:
            sess = {"event_count": 0, "credentials": [], "user_agents": set(), "max_severity": Severity.INFO.value}
            sessions[key] = sess
            sess["session_id"] = key
            sess["ip"] = (event.raw_payload or {}).get("client_ip")
            sess["first_seen"] = event.timestamp
            sess["events"] = []
        sess["last_seen"] = event.timestamp
        sess["event_count"] += 1
        sess["events"].append(_event_dict(event))
        ua = (event.raw_payload or {}).get("user_agent")
        if ua:
            sess["user_agents"].add(str(ua))
        if order[event.severity.value] > order[sess["max_severity"]]:
            sess["max_severity"] = event.severity.value
        if event.event_type == "honeypot.login_attempt":
            sess["credentials"].append({
                "usuario": (event.raw_payload or {}).get("usuario_probado"),
                "password": (event.raw_payload or {}).get("password_probada"),
                "at": event.timestamp,
            })
        step = (event.raw_payload or {}).get("step")
        if step:
            sess.setdefault("steps", []).append(str(step))

    result = []
    for key, sess in sessions.items():
        events_desc = sess["events"]
        duration = (sess["last_seen"] - sess["first_seen"]).total_seconds() if sess["first_seen"] else 0.0
        depth = _max_step_depth(events_desc)
        result.append({
            "session_id": key,
            "ip": sess["ip"],
            "first_seen": sess["first_seen"],
            "last_seen": sess["last_seen"],
            "duration_seconds": round(duration, 1),
            "event_count": sess["event_count"],
            "views": sum(1 for e in events_desc if e["event_type"] == "honeypot.view"),
            "login_attempts": len(sess["credentials"]),
            "max_severity": sess["max_severity"],
            "depth": depth,
            "steps": sess.get("steps", []),
            "credentials": sess["credentials"],
            "user_agents": sorted(sess["user_agents"]),
            "events": events_desc,
        })
    result.sort(key=lambda s: s["last_seen"], reverse=True)
    return result[:limit]


def _max_step_depth(events: Sequence[dict]) -> int:
    depth = 0
    for e in events:
        if e["event_type"] == "honeypot.login_attempt":
            depth = max(depth, 1)
        step = e.get("step")
        if step and f"honeypot.step:{step}" in _STEP_DEPTH:
            depth = max(depth, _STEP_DEPTH[f"honeypot.step:{step}"])
    return depth


def session_stats(sessions: Sequence[dict]) -> dict:
    """Resumen agregado para el panel: totales y medias que un SOC mira
    primero (cuánta gente cae, cuánto se quedan, hasta dónde llegan)."""
    total_sessions = len(sessions)
    login_attempts = sum(s["login_attempts"] for s in sessions)
    credentials = sum(len(s["credentials"]) for s in sessions)
    return {
        "total_sessions": total_sessions,
        "unique_ips": len({s["ip"] for s in sessions if s.get("ip")}),
        "login_attempts": login_attempts,
        "credentials_captured": credentials,
        "avg_duration_seconds": round(
            sum(s["duration_seconds"] for s in sessions) / total_sessions, 1
        ) if total_sessions else 0.0,
        "avg_depth": round(sum(s["depth"] for s in sessions) / total_sessions, 2) if total_sessions else 0,
        "total_events": sum(s["event_count"] for s in sessions),
        "max_duration_seconds": max(s["duration_seconds"] for s in sessions) if total_sessions else 0.0,
    }