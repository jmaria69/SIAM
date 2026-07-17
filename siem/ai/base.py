"""Interfaz común del motor de IA (módulo 2 y 9 del prompt original).

Cualquier proveedor (Claude, OpenAI, un LLM local, o ninguno) implementa esta
misma interfaz. Los routers nunca importan un SDK de IA directamente — solo
hablan con `AIProvider`. Esto es lo que permite que José elija "local, Claude,
OpenAI, cualquier LLM de pago" sin reescribir el resto del sistema.
"""
from abc import ABC, abstractmethod
from typing import List

from siem.models import ChatMessage, Incident, Role


class AIProvider(ABC):
    name: str = "base"

    @abstractmethod
    def chat(self, message: str, history: List[ChatMessage], user_role: Role) -> str:
        """Responde una pregunta libre del administrador, adaptando el nivel
        de detalle al rol (dirección vs. técnico vs. auditoría)."""

    @abstractmethod
    def explain_incident(self, incident: Incident) -> str:
        """Explica un incidente en lenguaje claro y recomienda mitigación."""

    @abstractmethod
    def summarize(self, title: str, data_points: List[str]) -> str:
        """Resume actividad (para informes diarios/semanales/mensuales)."""

    @abstractmethod
    def generate_campaign_content(self, topic: str, content_type: str, audience_hint: str = "") -> str:
        """Genera contenido para una campaña de concienciación: email de
        phishing SIMULADO (sin enlaces/credenciales reales), un comunicado,
        o preguntas de un quiz, según `content_type`. Es material de
        entrenamiento para empleados, nunca un intento real."""


ROLE_DETAIL_HINT = {
    Role.DIRECCION: "Responde en 2-4 frases, sin jerga técnica, orientado a impacto de negocio.",
    Role.AUDITOR: "Responde con precisión, citando estados y fechas, tono de cumplimiento.",
    Role.ANALISTA: "Responde con detalle técnico completo: activos, indicadores, pasos exactos.",
    Role.IT_RESPONSABLE: "Responde con foco operativo: qué hacer ahora y en qué orden.",
    Role.ADMIN: "Responde con detalle técnico moderado y próximos pasos claros.",
    Role.SUPERADMIN: "Responde con detalle técnico completo.",
}
