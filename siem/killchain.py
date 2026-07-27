"""Reconstrucción de la cadena de ataque (kill-chain) de un incidente.

Esta es la pieza diferencial de SIAM frente a Wazuh/Graylog/Security Onion:
no se queda en "hay alertas correlacionadas por activo" (eso ya lo hace
`siem/correlation.py`), sino que ORDENA esas señales como los pasos de un
ataque en el marco MITRE ATT&CK y las cuenta como una historia que un dueño
de pyme entiende sin tener un analista SOC delante.

Diseño en dos capas, igual que el resto del sistema:

  1. Capa determinista (esta, sin IA) -> `build_kill_chain`. Toma los eventos
     de un incidente, los mapea a su táctica/técnica ATT&CK vía el catálogo
     (`siem/threats_catalog.py`) y los ordena por la kill-chain canónica
     (de "cómo entró" a "qué impacto tuvo"). Funciona SIEMPRE, con
     AI_PROVIDER=none, y es auditable a simple vista -- misma filosofía que
     `threat_detection.py`.

  2. Capa de narración (opcional, IA) -> `AIProvider.narrate_kill_chain`.
     Convierte esos pasos en un relato en lenguaje llano. Si no hay IA
     configurada, `render_narrative_plain` da una versión de plantilla
     honesta en vez de fallar.

El router (`siem/router/incidents.py`) orquesta ambas: primero construye la
cadena determinista, luego pide la narración. Este módulo NO importa
`siem.ai` -> no hay ciclo de imports.
"""
from __future__ import annotations

from typing import List

from pydantic import BaseModel

from siem.models import Event, Incident
from siem.threats_catalog import get_threat, tactic_rank


class KillChainStep(BaseModel):
    """Un paso de la cadena de ataque: una técnica ATT&CK observada, anclada
    al primer evento que la evidenció (para poder decir "en el equipo X, a
    las HH:MM...")."""

    order: int                 # 1..N en orden de kill-chain
    tactic_id: str             # p.ej. "TA0001"
    tactic: str                # p.ej. "Acceso inicial"
    technique_id: str          # p.ej. "T1566"
    technique: str             # p.ej. "Phishing"
    threat_id: int             # id en siem/threats_catalog.py
    threat_name: str           # nombre legible de la amenaza del catálogo
    event_id: str              # evento que evidenció esta técnica (el más temprano)
    event_summary: str
    asset_name: str | None
    severity: str


def build_kill_chain(incident: Incident, events: List[Event]) -> List[KillChainStep]:
    """Construye la cadena determinista a partir de los eventos del incidente.

    Regla: por cada técnica ATT&CK distinta presente en el incidente se emite
    UN paso, anclado al evento MÁS TEMPRANO que la evidenció. Así la cadena no
    se repite aunque tres eventos disparen la misma amenaza, y cada paso apunta
    a evidencia real. El orden final es (posición en la kill-chain, luego
    tiempo del evento ancla) -> se lee de "cómo empezó" a "qué impacto tuvo".
    """
    # threat_id -> evento ancla (el más temprano que lo disparó)
    earliest_by_threat: dict[int, Event] = {}
    for event in sorted(events, key=lambda e: e.timestamp):
        for threat_id in event.threat_ids:
            if threat_id not in earliest_by_threat:
                earliest_by_threat[threat_id] = event

    steps: list[KillChainStep] = []
    for threat_id, event in earliest_by_threat.items():
        threat = get_threat(threat_id)
        if not threat:
            continue  # id fuera de catálogo: se ignora, no rompe la cadena
        steps.append(
            KillChainStep(
                order=0,  # se asigna tras ordenar
                tactic_id=threat["mitre_tactic_id"],
                tactic=threat["mitre_tactic"],
                technique_id=threat["mitre_technique_id"],
                technique=threat["mitre_technique"],
                threat_id=threat_id,
                threat_name=threat["nombre"],
                event_id=event.id,
                event_summary=event.summary,
                asset_name=event.asset_name,
                severity=event.severity.value,
            )
        )

    # Orden de kill-chain: primero la posición de la táctica en ATT&CK, luego
    # el instante del evento ancla como desempate estable.
    steps.sort(key=lambda s: (tactic_rank(s.tactic_id), earliest_by_threat[s.threat_id].timestamp))
    for i, step in enumerate(steps, start=1):
        step.order = i
    return steps


def render_steps_for_prompt(incident: Incident, steps: List[KillChainStep]) -> str:
    """Serializa la cadena en un texto compacto que un LLM puede leer para
    narrarla. No es lo que ve el usuario final -- es el input del modelo."""
    header = (
        f"Incidente {incident.id}: {incident.title}\n"
        f"Severidad: {incident.severity.value}. Riesgo: {incident.risk_score}/100.\n"
        f"Activos afectados: {', '.join(incident.affected_assets) or 'no especificados'}.\n"
        f"Pasos de la cadena de ataque reconstruida (orden MITRE ATT&CK):"
    )
    lines = [
        f"{s.order}. [{s.tactic} · {s.technique_id} {s.technique}] "
        f"{s.threat_name} — evidencia: '{s.event_summary}'"
        f"{f' en {s.asset_name}' if s.asset_name else ''} (severidad {s.severity})."
        for s in steps
    ]
    return header + "\n" + "\n".join(lines)


def render_narrative_plain(incident: Incident, steps: List[KillChainStep]) -> str:
    """Narración determinista (sin IA) para cuando AI_PROVIDER=none. Honesta
    sobre lo que es: una lectura ordenada de la cadena, no un relato generado.
    Prefiere esto a devolver vacío o fallar."""
    if not steps:
        return (
            f"No se pudo reconstruir una cadena de ataque para el incidente "
            f"{incident.id}: sus eventos no tienen amenazas del catálogo asociadas. "
            "Revisa los eventos correlacionados manualmente."
        )
    partes = [
        f"Cadena de ataque reconstruida para «{incident.title}» "
        f"({len(steps)} pasos, riesgo {incident.risk_score}/100):",
    ]
    for s in steps:
        ancla = f" en {s.asset_name}" if s.asset_name else ""
        partes.append(
            f"  {s.order}) {s.tactic}: {s.threat_name} "
            f"(ATT&CK {s.technique_id}){ancla} — «{s.event_summary}»."
        )
    tacticas = " → ".join(dict.fromkeys(s.tactic for s in steps))
    partes.append(
        f"Progresión de tácticas: {tacticas}. "
        "(Narración de plantilla: configura un proveedor de IA para un relato "
        "en lenguaje natural y recomendaciones adaptadas.)"
    )
    return "\n".join(partes)
