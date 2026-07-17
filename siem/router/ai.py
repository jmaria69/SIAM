"""Chat de IA (módulo 9)."""
from fastapi import APIRouter, Depends, HTTPException

from siem.ai import get_ai_provider
from siem.config import Settings, get_settings
from siem.models import ChatRequest
from siem.store import SiemStore, get_store

router = APIRouter(prefix="/v1/ai", tags=["ia"])


@router.post("/chat")
def chat(
    request: ChatRequest,
    store: SiemStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    provider = get_ai_provider(settings)

    # Si la pregunta viene ligada a un incidente, se añade contexto real —
    # así el chat no alucina datos que ya tenemos en el store.
    contextual_message = request.message
    if request.incident_id:
        incident = store.get_incident(request.incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incidente no encontrado")
        contextual_message = (
            f"[Contexto del incidente {incident.id}: título='{incident.title}', "
            f"severidad={incident.severity.value}, estado={incident.status.value}, "
            f"riesgo={incident.risk_score}/100] Pregunta: {request.message}"
        )

    # Mismo caso que en incidents.explain_incident: get_ai_provider solo
    # protege la inicialización; un fallo del proveedor en tiempo de llamada
    # (p.ej. el contenedor no llega a Ollama) salía como 500 pelado y el chat
    # se quedaba mudo. Se convierte en 502 con detalle legible para la UI.
    try:
        answer = provider.chat(contextual_message, request.history, request.user_role)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502,
            detail=(
                f"El proveedor de IA '{provider.name}' no respondió ({type(exc).__name__}). "
                "Revisa AI_PROVIDER y su configuración (API key / LOCAL_LLM_URL) en el servidor."
            ),
        ) from exc
    return {"proveedor_ia": provider.name, "respuesta": answer}
