"""Detección de amenazas por palabra clave (2026-07-05).

Decisión explícita de José: reglas por palabra clave, no clasificación vía
IA -- determinista, sin coste de inferencia, funciona siempre (incluso con
AI_PROVIDER=none), y es auditable a simple vista igual que
`siem/correlation.py`. Si en el futuro se quiere IA como refuerzo para los
eventos que no matchean ninguna keyword, este módulo es el sitio natural
para añadirlo -- ver `detect_threats`, que ya devuelve lista vacía en ese
caso en vez de fallar.
"""
import unicodedata

from siem.models import Event
from siem.threats_catalog import THREATS_CATALOG


def _normalize(text: str) -> str:
    """minúsculas + sin acentos. Bug real evitado en la propia ronda de
    escritura del catálogo: keywords como "camara comprometida" (sin
    acento) no casaban contra "Cámara comprometida" en el texto de un
    escenario del simulador (con acento) -- son cadenas distintas para un
    `in` normal. En vez de perseguir a mano cada par acento/sin-acento en
    threats_catalog.py y siem/scenarios.py, se normaliza una vez aquí y
    listo: funciona sin importar si quien redactó el summary/keyword puso
    o no la tilde."""
    text = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in text if not unicodedata.combining(c))


def detect_threats(event: Event) -> list[int]:
    """Compara event_type + summary + description contra las keywords de
    cada amenaza del catálogo (comparación insensible a mayúsculas y
    acentos). Devuelve los ids de las amenazas que hicieron match, en el
    mismo orden que el catálogo (no por relevancia -- con un catálogo de 30
    entradas no hace falta rankear, y mantener el orden del catálogo hace
    la salida predecible para los tests)."""
    haystack = _normalize(
        " ".join(filter(None, [event.event_type, event.summary, event.description]))
    )

    return [
        threat["id"]
        for threat in THREATS_CATALOG
        if any(_normalize(keyword) in haystack for keyword in threat["keywords"])
    ]
