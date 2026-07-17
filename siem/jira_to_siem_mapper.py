import uuid
from typing import Dict, Any

# Importar el modelo Pydantic que usamos en la API
from siem.models import SiemTicket


def map_jira_to_siem(jira_payload: Dict[Any, Any]) -> SiemTicket:
    """Convierte el payload de JIRA al modelo interno SiemTicket.

    Se extraen los campos más relevantes y se asignan a nuestro modelo.
    El campo `service` se fija a "JIRA" por defecto (puede ajustarse según
    la lógica de negocio). El `ticket_id` se mapea al `external_id` de JIRA.
    """
    issue = jira_payload.get("issue", {})
    fields = issue.get("fields", {})

    jira_status = fields.get("status", {}).get("name", "NUEVO").upper().replace(" ", "_")
    jira_priority = fields.get("priority", {}).get("name", "MEDIA").upper()

    status_mapping = {
        "TO_DO": "NUEVO",
        "IN_PROGRESS": "EN_PROGRESO",
        "DONE": "RESUELTO",
    }
    siem_status = status_mapping.get(jira_status, "NUEVO")

    # Construir el SiemTicket esperado por la API
    return SiemTicket(
        ticket_id=issue.get("key", f"T-{uuid.uuid4().hex[:6].upper()}"),
        service="JIRA",
        description=fields.get("description", "Sin descripción"),
        priority=jira_priority,
        status=siem_status,
        # El campo `summary` no está en nuestro modelo Pydantic, lo omitimos.
    )
