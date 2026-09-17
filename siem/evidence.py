"""Expediente de Defensa: ledger de evidencias encadenado por hash + dossier
de cumplimiento (cuestionario de ciberseguro / auditoría NIS2).

El porqué, en una frase: SIAM ya genera la evidencia que piden la
aseguradora y el auditor, pero no la guardaba. Los módulos PYME
(siem/course_cybersecurity.py) son calculadoras de un solo uso, los informes
(siem/router/reports.py) se construyen al vuelo, y los bloqueos reales solo
dejaban un IOC sin fecha de la acción. Este módulo convierte esos hechos en
un registro fechado, inmutable-por-detección y consultable.

Dos capas, deliberadamente separadas:

1. **El ledger** (`record`/`verify_chain`): hechos puntuales que de otro modo
   se perderían -- una acción de respuesta ejecutada, un incidente contenido,
   un documento generado. Append-only y encadenado por hash.
2. **El dossier** (`build_dossier`): la lectura de cumplimiento, que combina
   el ledger con agregados en vivo del store. NO se persiste: se recalcula
   para el periodo que pida el usuario, igual que hace
   store.attack_metrics con las métricas de ataque.

La regla de honestidad que gobierna todo el módulo: cada control se marca
como `probado` (hay telemetría operativa real), `declarado` (solo hay un
documento o una autoevaluación) o `sin_evidencia`. Nunca se sugiere
responder "sí" a un cuestionario sobre la base de un documento cuando la
pregunta esperaba prueba operativa: una respuesta materialmente falsa en una
solicitud de ciberseguro permite a la aseguradora rescindir la póliza desde
su origen, que es peor que no tener póliza. Ver `respuesta_sugerida`.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Optional

from siem.models import Evidence, EvidenceKind

# ---------------------------------------------------------------------------
# Encadenado por hash
# ---------------------------------------------------------------------------

def canonical_payload(record: Evidence) -> str:
    """Serialización determinista de una evidencia, para hashear siempre lo
    mismo ante los mismos datos. `sort_keys` fija el orden de las claves
    (SQLite devuelve el JSON tal cual se guardó, pero un dict de Python no
    garantiza orden estable entre procesos) y `default=str` cubre los
    datetime que se cuelen dentro de `payload`.

    `seq` queda fuera a propósito -- ver el docstring de
    db_models.EvidenceDB: lo asigna SQLite en el INSERT, así que no se
    conoce todavía cuando se calcula el hash. El orden lo fija prev_hash.
    """
    return json.dumps(
        {
            "id": record.id,
            "recorded_at": record.recorded_at.isoformat(),
            "kind": record.kind.value,
            "control_ids": sorted(record.control_ids),
            "title": record.title,
            "summary": record.summary,
            "payload": record.payload,
            "source_ref": record.source_ref,
            "actor": record.actor,
            "prev_hash": record.prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def compute_hash(record: Evidence) -> str:
    return hashlib.sha256(canonical_payload(record).encode("utf-8")).hexdigest()


def record(store, entry: Evidence) -> Evidence:
    """Encadena y persiste una evidencia. Único camino de escritura al
    ledger -- los hooks (siem/response_actions.py, los routers) llaman aquí,
    nunca a store.add_evidence directamente, para que ninguna fila pueda
    entrar sin hash.

    Nunca lanza hacia arriba: registrar evidencia es un efecto secundario de
    operaciones que deben seguir funcionando aunque el ledger falle (un
    bloqueo de Cloudflare ya ejecutado no se puede "deshacer" porque no se
    haya podido escribir su evidencia). Si falla, devuelve el record sin
    hash y el fallo se ve en /v1/evidence/verify como un hueco.
    """
    try:
        entry.prev_hash = store.last_evidence_hash()
        entry.hash = compute_hash(entry)
        return store.add_evidence(entry)
    except Exception:  # noqa: BLE001 -- ver docstring: nunca rompe al caller
        return entry


def verify_chain(store) -> dict:
    """Recorre el ledger entero recalculando los hashes. Devuelve el primer
    punto de ruptura, que es lo único accionable: a partir de ahí todo lo
    posterior es sospechoso aunque su propio hash cuadre.

    Dos formas de ruptura, distinguidas a propósito porque significan cosas
    distintas: `hash_alterado` = alguien cambió el contenido de una fila
    (UPDATE directo en SQLite); `cadena_rota` = el enlace no apunta a la
    fila anterior (una fila borrada o insertada por fuera de `record`).
    """
    records = store.list_evidence(limit=None)
    prev_hash: Optional[str] = None
    for entry in records:
        if entry.prev_hash != prev_hash:
            return {
                "integra": False,
                "motivo": "cadena_rota",
                "total": len(records),
                "rota_en": entry.id,
                "detalle": (
                    f"La evidencia {entry.id} no enlaza con la anterior "
                    f"(esperaba prev_hash={prev_hash}, tiene {entry.prev_hash}). "
                    "Indica una fila borrada o insertada fuera del registro."
                ),
            }
        if compute_hash(entry) != entry.hash:
            return {
                "integra": False,
                "motivo": "hash_alterado",
                "total": len(records),
                "rota_en": entry.id,
                "detalle": (
                    f"El contenido de la evidencia {entry.id} no coincide con su hash: "
                    "la fila se modificó después de registrarse."
                ),
            }
        prev_hash = entry.hash
    return {
        "integra": True,
        "motivo": None,
        "total": len(records),
        "rota_en": None,
        "detalle": (
            f"Cadena íntegra: {len(records)} evidencia(s) verificadas."
            if records
            else "Ledger vacío: todavía no hay evidencias registradas."
        ),
    }


# ---------------------------------------------------------------------------
# Catálogo de controles
# ---------------------------------------------------------------------------
# Los ids c1..c15 son los MISMOS que el checklist de auditoría que ya existía
# (siem/course_cybersecurity.py::get_audit_checklist) -- se reutilizan a
# propósito para que la autoevaluación de la pyme y la evidencia operativa
# hablen del mismo control y el dossier pueda contrastarlas ("marcaste c9
# como cumplido y además el WAF bloqueó 1.243 ataques" vs "marcaste c10 como
# cumplido pero no hay ninguna evidencia").
#
# s1..s3 son controles propios de SIAM que el checklist de 15 no cubre y que
# sí pregunta toda aseguradora: monitorización continua, contención de
# incidentes y detección temprana por señuelos. s3 es el diferenciador --
# casi ninguna pyme puede aportar prueba de deception.
# ---------------------------------------------------------------------------

class Control:
    """Un control del expediente. `evidencia_operativa` marca si SIAM puede
    PROBARLO con telemetría o solo recoger la declaración del cliente."""

    def __init__(
        self,
        id: str,
        categoria: str,
        titulo: str,
        pregunta_aseguradora: str,
        referencia: str,
        evidencia_operativa: bool,
    ) -> None:
        self.id = id
        self.categoria = categoria
        self.titulo = titulo
        self.pregunta_aseguradora = pregunta_aseguradora
        self.referencia = referencia
        self.evidencia_operativa = evidencia_operativa


CONTROLS: dict[str, Control] = {
    "s1": Control(
        id="s1",
        categoria="Monitorización",
        titulo="Monitorización continua de seguridad con registro de eventos conservado.",
        pregunta_aseguradora="¿Dispone de monitorización de seguridad continua y conserva los registros de eventos?",
        referencia="NIS2 art. 21.2.b) — gestión de incidentes",
        evidencia_operativa=True,
    ),
    "s2": Control(
        id="s2",
        categoria="Respuesta a incidentes",
        titulo="Incidentes gestionados y contenidos, con cadena de ataque documentada.",
        pregunta_aseguradora="¿Tiene un plan de respuesta a incidentes probado? ¿Cuál es su tiempo medio de contención?",
        referencia="NIS2 art. 21.2.b) y art. 23 — notificación de incidentes",
        evidencia_operativa=True,
    ),
    "s3": Control(
        id="s3",
        categoria="Detección temprana",
        titulo="Señuelos (deception) desplegados para detectar intrusos antes del impacto.",
        pregunta_aseguradora="¿Emplea tecnología de engaño o señuelos para la detección temprana de intrusiones?",
        referencia="NIS2 art. 21.2.a) — análisis de riesgos y seguridad de los sistemas",
        evidencia_operativa=True,
    ),
    "c9": Control(
        id="c9",
        categoria="Seguridad Web",
        titulo="Aplicaciones web y tienda online protegidas por WAF contra SQLi, XSS y CSRF.",
        pregunta_aseguradora="¿Protege sus aplicaciones web con un firewall de aplicación (WAF) activo?",
        referencia="NIS2 art. 21.2.e) — seguridad en adquisición y mantenimiento de sistemas",
        evidencia_operativa=True,
    ),
    "c15": Control(
        id="c15",
        categoria="Formación y Concienciación",
        titulo="Formación regular en ciberseguridad y simulacros de phishing al personal.",
        pregunta_aseguradora="¿Imparte formación periódica en seguridad y realiza simulacros de phishing? Aporte tasas de clic y reporte.",
        referencia="NIS2 art. 21.2.g) — higiene y formación en ciberseguridad",
        evidencia_operativa=True,
    ),
    "c1": Control(
        id="c1",
        categoria="Políticas y PDS",
        titulo="Plan Director de Seguridad (PDS) formalizado y revisado al menos una vez al año.",
        pregunta_aseguradora="¿Dispone de una política de seguridad de la información formalizada y aprobada por la dirección?",
        referencia="NIS2 art. 20 — gobernanza y responsabilidad de la dirección",
        evidencia_operativa=False,
    ),
    "c11": Control(
        id="c11",
        categoria="Backup y DRP",
        titulo="Pruebas periódicas de restauración con métricas RTO y RPO definidas.",
        pregunta_aseguradora="¿Prueba periódicamente la restauración de sus copias de seguridad? Aporte fecha y resultado de la última prueba.",
        referencia="NIS2 art. 21.2.c) — continuidad de negocio y gestión de copias",
        evidencia_operativa=False,
    ),
    "c4": Control(
        id="c4",
        categoria="Control de Acceso",
        titulo="MFA obligatoria en accesos remotos, VPN y cuentas administrativas.",
        pregunta_aseguradora="¿Exige MFA en TODOS los accesos remotos, correo y cuentas con privilegios?",
        referencia="NIS2 art. 21.2.j) — autenticación multifactor",
        evidencia_operativa=False,
    ),
}

# Orden de presentación en el dossier: primero lo que SIAM prueba de verdad
# (es el argumento de venta y lo que la aseguradora descuenta), después lo
# documental.
CONTROL_ORDER = ["s1", "s2", "s3", "c9", "c15", "c1", "c11", "c4"]

# Qué hacer cuando un control se queda sin evidencia. Texto accionable, no
# "revise el control X": el destinatario del dossier es el gerente de una
# pyme que tiene la renovación de la póliza en tres semanas.
PENDIENTE = {
    "s1": "Sin eventos en el periodo. Verifique que la ingesta (WAF/Cloudflare) está activa.",
    "s2": "No hay incidentes contenidos en el periodo. Si no hubo incidentes, indíquelo así en el cuestionario.",
    "s3": "Active el señuelo de Active Defense para poder acreditar detección temprana.",
    "c9": "No consta actividad del WAF. Compruebe el conector de Cloudflare/Coraza.",
    "c15": "Lance una campaña de simulacro de phishing: es el control con más peso en la prima.",
    "c1": "Genere el Plan Director de Seguridad desde el panel de Ciberseguridad PYME.",
    "c11": "Registre la última prueba de restauración como evidencia manual, con fecha y resultado.",
    "c4": "Registre como evidencia manual la captura de su consola (M365/Google) con el MFA exigido.",
}


def _period_bounds(records, date_from, date_to):
    return [
        r for r in records
        if (date_from is None or r.recorded_at >= date_from)
        and (date_to is None or r.recorded_at <= date_to)
    ]


def _mttr_horas(incidents) -> Optional[float]:
    """Tiempo medio de contención en horas sobre los incidentes ya resueltos.
    None si ninguno lo está -- un MTTR de 0 sería mentir por omisión."""
    deltas = [
        (i.resolved_at - i.created_at).total_seconds()
        for i in incidents
        if i.resolved_at is not None and i.resolved_at >= i.created_at
    ]
    if not deltas:
        return None
    return round(sum(deltas) / len(deltas) / 3600, 1)


def build_dossier(store, *, date_from: datetime, date_to: datetime) -> dict:
    """Expediente de cumplimiento para el periodo dado.

    No se persiste (se recalcula en cada petición, igual que
    store.attack_metrics) por dos motivos: el periodo lo elige quien rellena
    el cuestionario, y el ledger es la única fuente de verdad -- un dossier
    guardado podría quedar desalineado con él y sería justo el tipo de
    documento que una aseguradora rebate.
    """
    from siem.active_defense import WAF_SOURCES
    from siem.models import OPERATIONAL_KINDS

    ledger = _period_bounds(store.list_evidence(limit=None), date_from, date_to)
    waf_events = store.list_events(limit=20000, sources=WAF_SOURCES, date_from=date_from, date_to=date_to)
    honeypot_events = store.list_honeypot_events(date_from=date_from, date_to=date_to)
    incidents = [i for i in store.list_incidents() if date_from <= i.created_at <= date_to]
    campaigns = [c for c in store.list_campaigns() if date_from <= c.created_at <= date_to]
    blocked_ips = [ioc for ioc in store.list_iocs() if ioc.type == "ip"]

    honeypot_ips = {(e.raw_payload or {}).get("client_ip") for e in honeypot_events}
    honeypot_ips.discard(None)
    contenidos = [i for i in incidents if i.resolved_at is not None]
    mttr = _mttr_horas(incidents)
    enviados = sum(
        1 for c in campaigns for t in c.targets if t.status.value in ("enviado", "clic", "reportado", "completado")
    )
    clics = sum(1 for c in campaigns for t in c.targets if t.status.value == "clic")

    # Métrica operativa por control. `None` = no hay nada que probar; el
    # control cae a documental o a sin_evidencia según el ledger.
    metricas: dict[str, Optional[str]] = {
        "s1": (
            f"{len(waf_events) + len(honeypot_events)} evento(s) de seguridad registrados y conservados."
            if waf_events or honeypot_events else None
        ),
        "s2": (
            f"{len(contenidos)} de {len(incidents)} incidente(s) contenidos"
            + (f", tiempo medio de contención {mttr} h." if mttr is not None else ".")
            if incidents else None
        ),
        "s3": (
            f"{len(honeypot_events)} interacción(es) con el señuelo desde {len(honeypot_ips)} IP(s) distintas."
            if honeypot_events else None
        ),
        "c9": (
            f"{len(waf_events)} ataque(s) detectados por el WAF; {len(blocked_ips)} IP(s) con respuesta activa vigente."
            if waf_events else None
        ),
        "c15": (
            f"{len(campaigns)} campaña(s) de concienciación, {enviados} envío(s), tasa de clic "
            f"{round(clics / enviados * 100, 1) if enviados else 0}%."
            if campaigns else None
        ),
    }

    controles = []
    for control_id in CONTROL_ORDER:
        control = CONTROLS[control_id]
        evidencias = [e for e in ledger if control_id in e.control_ids]
        operativas = [e for e in evidencias if e.kind in OPERATIONAL_KINDS]
        metrica = metricas.get(control_id)

        if control.evidencia_operativa and (metrica or operativas):
            estado = "probado"
            prueba = "operativa"
            respuesta = f"Sí — {metrica}" if metrica else "Sí, acreditado por la telemetría del SOC."
            if evidencias:
                respuesta += f" Respaldado por {len(evidencias)} registro(s) del expediente."
        elif evidencias:
            estado = "declarado"
            prueba = "documental"
            respuesta = (
                "Sí, documentado — pero SIN prueba operativa en el periodo. "
                "Adjunte el documento y no afirme que el control se ha verificado en funcionamiento."
            )
        else:
            estado = "sin_evidencia"
            prueba = None
            respuesta = (
                "No responda «sí»: no hay ninguna evidencia en el expediente que lo respalde. "
                "Una respuesta materialmente falsa permite a la aseguradora rescindir la póliza."
            )

        controles.append({
            "id": control.id,
            "categoria": control.categoria,
            "titulo": control.titulo,
            "pregunta_aseguradora": control.pregunta_aseguradora,
            "referencia": control.referencia,
            "estado": estado,
            "prueba": prueba,
            "metrica": metrica,
            "respuesta_sugerida": respuesta,
            "pendiente": PENDIENTE[control.id] if estado == "sin_evidencia" else None,
            "evidencias": [
                {"id": e.id, "fecha": e.recorded_at, "titulo": e.title, "tipo": e.kind.value}
                for e in evidencias[-10:]
            ],
            "total_evidencias": len(evidencias),
        })

    resumen = {
        "probados": sum(1 for c in controles if c["estado"] == "probado"),
        "declarados": sum(1 for c in controles if c["estado"] == "declarado"),
        "sin_evidencia": sum(1 for c in controles if c["estado"] == "sin_evidencia"),
        "total": len(controles),
    }

    return {
        "generado_el": datetime.utcnow(),
        "periodo": {"desde": date_from, "hasta": date_to},
        "integridad": verify_chain(store),
        "resumen": resumen,
        "controles": controles,
        "evidencias_en_periodo": len(ledger),
    }
