"""Implementaciones concretas de AIProvider: Anthropic, OpenAI, LLM local
(cualquier endpoint compatible con la API de OpenAI, p.ej. Ollama o LM
Studio) y un fallback basado en reglas que no requiere ninguna API key.

El fallback importa porque el MVP tiene que poder demostrarse sin que José
tenga que pagar por un LLM primero. AI_PROVIDER=none (o cualquier provider
sin su API key configurada) cae automáticamente en él.
"""
from __future__ import annotations

from typing import List

from siem.ai.base import ROLE_DETAIL_HINT, AIProvider
from siem.config import Settings
from siem.models import ChatMessage, Incident, Role

SYSTEM_PROMPT_TEMPLATE = (
    "Eres el analista de IA de un SOC virtual para una pyme (SIEM Security). "
    "Explicas alertas de seguridad en lenguaje claro, priorizas por riesgo real "
    "y recomiendas acciones de mitigación. Nunca afirmas haber ejecutado una "
    "acción sobre los sistemas del cliente: solo recomiendas, la ejecución "
    "requiere confirmación humana explícita. {role_hint}"
)

# Contenido de campañas de concienciación: el destinatario final de un email
# de phishing simulado es un empleado que TIENE que poder confundirlo con uno
# real (ese es el ejercicio) — pero el modelo debe generarlo sabiendo que es
# para entrenamiento, sin enlaces ni credenciales reales.
CAMPAIGN_SYSTEM_SUFFIX = (
    " Ahora tu tarea es generar material de concienciación en seguridad para "
    "empleados de una pyme. Es contenido de ENTRENAMIENTO/SIMULACRO, nunca un "
    "intento real: si generas un email de phishing simulado, debe parecer "
    "realista para que sirva de prueba, pero usa siempre '[ENLACE_SIMULACRO]' "
    "como placeholder de enlace y no pidas ni incluyas credenciales reales."
)
# Narración de la kill-chain: el modelo recibe los pasos ATT&CK ya ordenados
# de forma determinista (no los infiere él) y su única tarea es contarlos como
# una historia que el dueño de una pyme entienda. Se le prohíbe inventar pasos
# fuera de la lista para que el relato no se desvíe de la evidencia real.
KILL_CHAIN_SYSTEM_SUFFIX = (
    " Ahora te doy la cadena de ataque de un incidente YA reconstruida y ordenada "
    "según MITRE ATT&CK. Nárrala como una historia breve y clara para alguien sin "
    "conocimientos técnicos: qué pasó primero, cómo progresó y qué impacto tuvo o "
    "pudo tener. No inventes pasos que no estén en la lista ni cambies su orden. "
    "Termina con las 2-3 acciones de contención más urgentes, en imperativo. "
    "Recuerda: solo recomiendas, no ejecutas nada."
)
CAMPAIGN_PROMPTS = {
    "email_phishing": (
        "Genera un email de phishing SIMULADO realista (asunto + cuerpo) sobre el tema "
        "indicado, con '[ENLACE_SIMULACRO]' como único enlace, para probar si los "
        "empleados lo detectan.\nTema: {topic}\nPúblico objetivo: {audience}"
    ),
    "quiz": (
        "Genera 5 preguntas de un quiz corto de concienciación en seguridad sobre el "
        "tema indicado, con la respuesta correcta marcada al final de cada una.\n"
        "Tema: {topic}\nPúblico objetivo: {audience}"
    ),
    "comunicado": (
        "Genera un comunicado breve y claro de concienciación en seguridad sobre el "
        "tema indicado, en tono profesional y cercano, para enviar a empleados.\n"
        "Tema: {topic}\nPúblico objetivo: {audience}"
    ),
}


class RuleBasedProvider(AIProvider):
    """Sin dependencias externas. Explica incidentes con una plantilla —
    honesto sobre sus límites: no es IA generativa, es la red de seguridad
    para que el producto funcione sin ninguna API key configurada."""

    name = "reglas (sin proveedor de IA configurado)"

    def chat(self, message: str, history: List[ChatMessage], user_role: Role) -> str:
        return (
            "No hay un proveedor de IA configurado (AI_PROVIDER=none o sin API key). "
            "Configura ANTHROPIC_API_KEY, OPENAI_API_KEY o LOCAL_LLM_URL en .env para "
            "respuestas generadas por IA. Mientras tanto: tu pregunta fue "
            f"'{message}'. Consulta /v1/incidents y /v1/monitoring/overview para "
            "los datos crudos."
        )

    def explain_incident(self, incident: Incident) -> str:
        lines = [
            f"Incidente {incident.id}: {incident.title}.",
            f"Severidad: {incident.severity.value}. Estado: {incident.status.value}.",
            f"Activos afectados: {', '.join(incident.affected_assets) or 'no especificados'}.",
            f"Eventos correlacionados: {len(incident.event_ids)}.",
            f"Score de riesgo: {incident.risk_score}/100.",
            "Recomendación genérica (sin IA configurada): investigar los activos "
            "afectados, verificar si hay accesos no autorizados y documentar la "
            "línea temporal antes de cerrar el incidente.",
        ]
        return "\n".join(lines)

    def summarize(self, title: str, data_points: List[str]) -> str:
        body = "\n".join(f"- {p}" for p in data_points) or "- Sin actividad relevante en el período."
        return f"{title}\n{body}"

    def generate_campaign_content(self, topic: str, content_type: str, audience_hint: str = "") -> str:
        aviso = "(Sin proveedor de IA configurado: plantilla genérica, no adaptada a tu empresa.)"
        if content_type == "email_phishing":
            return (
                f"[SIMULACRO DE PHISHING — tema: {topic}]\n"
                "Asunto: Verificación de cuenta requerida\n\n"
                "Hola,\n\nHemos detectado actividad inusual en tu cuenta. Verifica tu identidad "
                "cuanto antes para evitar la suspensión del acceso:\n[ENLACE_SIMULACRO]\n\n"
                f"{aviso}"
            )
        if content_type == "quiz":
            return (
                f"[QUIZ DE CONCIENCIACIÓN — tema: {topic}]\n"
                "1. ¿Qué haces si recibes un correo pidiendo tu contraseña con urgencia?\n"
                "2. ¿Cómo verificas que un remitente es legítimo antes de hacer clic?\n"
                "3. ¿A quién reportas un correo o mensaje sospechoso?\n"
                f"{aviso}"
            )
        return (
            f"[COMUNICADO DE CONCIENCIACIÓN — tema: {topic}]\n"
            "Recuerda: no compartas contraseñas por email ni chat, verifica siempre el remitente "
            "real antes de hacer clic, y reporta cualquier actividad sospechosa al equipo de "
            f"seguridad en vez de ignorarla.\n{aviso}"
        )


class AnthropicProvider(AIProvider):
    name = "anthropic"

    def __init__(self, settings: Settings):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "AI_PROVIDER=anthropic pero el paquete 'anthropic' no está instalado. "
                "pip install anthropic"
            ) from exc
        if not settings.ANTHROPIC_API_KEY:
            raise RuntimeError("AI_PROVIDER=anthropic requiere ANTHROPIC_API_KEY en .env")
        self._client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        self._model = settings.ANTHROPIC_MODEL

    def _complete(self, system: str, user_content: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=800,
            system=system,
            messages=[{"role": "user", "content": user_content}],
        )
        return "".join(block.text for block in response.content if getattr(block, "type", "") == "text")

    def chat(self, message: str, history: List[ChatMessage], user_role: Role) -> str:
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint=ROLE_DETAIL_HINT.get(user_role, ""))
        transcript = "\n".join(f"{m.role}: {m.content}" for m in history)
        user_content = f"{transcript}\nusuario: {message}" if transcript else message
        return self._complete(system, user_content)

    def explain_incident(self, incident: Incident) -> str:
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint="")
        prompt = (
            f"Explica este incidente de seguridad y recomienda mitigación en lenguaje claro:\n"
            f"Título: {incident.title}\nSeveridad: {incident.severity.value}\n"
            f"Descripción: {incident.description}\nActivos afectados: {incident.affected_assets}\n"
            f"Eventos correlacionados: {len(incident.event_ids)}\nRiesgo actual: {incident.risk_score}/100"
        )
        return self._complete(system, prompt)

    def summarize(self, title: str, data_points: List[str]) -> str:
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint="")
        prompt = f"Resume esta actividad para un informe titulado '{title}':\n" + "\n".join(data_points)
        return self._complete(system, prompt)

    def narrate_kill_chain(self, incident, steps) -> str:
        from siem.killchain import render_narrative_plain, render_steps_for_prompt

        if not steps:  # nada que narrar: no gastes una llamada al modelo
            return render_narrative_plain(incident, steps)
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint="") + KILL_CHAIN_SYSTEM_SUFFIX
        return self._complete(system, render_steps_for_prompt(incident, steps))

    def generate_campaign_content(self, topic: str, content_type: str, audience_hint: str = "") -> str:
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint="") + CAMPAIGN_SYSTEM_SUFFIX
        prompt = CAMPAIGN_PROMPTS.get(content_type, CAMPAIGN_PROMPTS["comunicado"]).format(
            topic=topic, audience=audience_hint or "empleados en general"
        )
        return self._complete(system, prompt)


class OpenAIProvider(AIProvider):
    name = "openai"

    # Sobreescribibles por subclases (LocalProvider los sube: los modelos
    # locales tipo Qwen3 son "razonadores" y pueden gastarse el presupuesto
    # de tokens entero pensando en <think>...</think> antes de responder,
    # dejando `message.content` vacío si el límite es bajo).
    max_tokens = 800
    extra_body: dict | None = None

    def __init__(self, settings: Settings):
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "AI_PROVIDER=openai pero el paquete 'openai' no está instalado. pip install openai"
            ) from exc
        if not settings.OPENAI_API_KEY:
            raise RuntimeError("AI_PROVIDER=openai requiere OPENAI_API_KEY en .env")
        self._client = OpenAI(api_key=settings.OPENAI_API_KEY)
        self._model = settings.OPENAI_MODEL

    def _complete(self, system: str, user_content: str) -> str:
        kwargs = {}
        if self.extra_body:
            kwargs["extra_body"] = self.extra_body
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user_content}],
            max_tokens=self.max_tokens,
            **kwargs,
        )
        content = response.choices[0].message.content or ""
        if not content.strip():
            # Vacío de verdad (no solo espacios): probablemente un modelo
            # razonador que se quedó sin tokens pensando, o devolvió el
            # razonamiento en otro campo que este cliente no está leyendo.
            # Mejor decir esto claramente que enseñar una burbuja en blanco.
            finish_reason = getattr(response.choices[0], "finish_reason", "desconocido")
            content = (
                f"[{self.name}] El modelo respondió vacío (finish_reason={finish_reason}). "
                "Si es un modelo razonador (Qwen3, DeepSeek-R1...), probablemente agotó "
                "max_tokens pensando antes de escribir la respuesta final — sube "
                "max_tokens en siem/ai/providers.py o desactiva el modo 'thinking' "
                "en el servidor local si lo soporta."
            )
        return content

    def chat(self, message: str, history: List[ChatMessage], user_role: Role) -> str:
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint=ROLE_DETAIL_HINT.get(user_role, ""))
        transcript = "\n".join(f"{m.role}: {m.content}" for m in history)
        user_content = f"{transcript}\nusuario: {message}" if transcript else message
        return self._complete(system, user_content)

    def explain_incident(self, incident: Incident) -> str:
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint="")
        prompt = (
            f"Explica este incidente de seguridad y recomienda mitigación en lenguaje claro:\n"
            f"Título: {incident.title}\nSeveridad: {incident.severity.value}\n"
            f"Descripción: {incident.description}\nActivos afectados: {incident.affected_assets}\n"
            f"Eventos correlacionados: {len(incident.event_ids)}\nRiesgo actual: {incident.risk_score}/100"
        )
        return self._complete(system, prompt)

    def summarize(self, title: str, data_points: List[str]) -> str:
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint="")
        prompt = f"Resume esta actividad para un informe titulado '{title}':\n" + "\n".join(data_points)
        return self._complete(system, prompt)

    def narrate_kill_chain(self, incident, steps) -> str:
        from siem.killchain import render_narrative_plain, render_steps_for_prompt

        if not steps:  # nada que narrar: no gastes una llamada al modelo
            return render_narrative_plain(incident, steps)
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint="") + KILL_CHAIN_SYSTEM_SUFFIX
        return self._complete(system, render_steps_for_prompt(incident, steps))

    def generate_campaign_content(self, topic: str, content_type: str, audience_hint: str = "") -> str:
        system = SYSTEM_PROMPT_TEMPLATE.format(role_hint="") + CAMPAIGN_SYSTEM_SUFFIX
        prompt = CAMPAIGN_PROMPTS.get(content_type, CAMPAIGN_PROMPTS["comunicado"]).format(
            topic=topic, audience=audience_hint or "empleados en general"
        )
        return self._complete(system, prompt)


class LocalProvider(OpenAIProvider):
    """Cualquier servidor local compatible con la API de OpenAI (Ollama,
    LM Studio, vLLM con el adaptador openai...). Reutiliza OpenAIProvider
    apuntando `base_url` al endpoint local — no hay que reimplementar nada.

    max_tokens más alto y `think: false` porque en pruebas con Ollama +
    qwen36-27b (un modelo razonador tipo Qwen3) el `message.content` volvía
    vacío: se gastaba los 800 tokens del límite anterior en el bloque de
    razonamiento interno y nunca llegaba a escribir la respuesta final.
    `think: false` es un campo que Ollama entiende para esta familia de
    modelos; si el servidor local no lo reconoce, se ignora sin más (no
    rompe nada) — por eso no hace daño mandarlo siempre.
    """

    name = "local"
    max_tokens = 2048
    extra_body = {"think": False}

    def __init__(self, settings: Settings):
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "AI_PROVIDER=local pero el paquete 'openai' no está instalado (se usa como "
                "cliente genérico compatible). pip install openai"
            ) from exc
        if not settings.LOCAL_LLM_URL:
            raise RuntimeError("AI_PROVIDER=local requiere LOCAL_LLM_URL en .env, p.ej. http://localhost:11434/v1")
        self._client = OpenAI(api_key="local-no-key-needed", base_url=settings.LOCAL_LLM_URL)
        self._model = settings.LOCAL_LLM_MODEL


def get_ai_provider(settings: Settings) -> AIProvider:
    """Factory: decide el proveedor según AI_PROVIDER, con fallback seguro a
    reglas si falta configuración (nunca rompe el arranque de la app)."""
    try:
        if settings.AI_PROVIDER == "anthropic":
            return AnthropicProvider(settings)
        if settings.AI_PROVIDER == "openai":
            return OpenAIProvider(settings)
        if settings.AI_PROVIDER == "local":
            return LocalProvider(settings)
    except RuntimeError as exc:
        import logging

        logging.getLogger("siem.ai").warning("No se pudo inicializar %s: %s. Usando RuleBasedProvider.", settings.AI_PROVIDER, exc)
    return RuleBasedProvider()
