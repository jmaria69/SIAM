"""Automatización de flujos de trabajo (módulo 6).

Cualquier acción que pueda afectar a sistemas del cliente requiere
`confirm=true` explícito en la query string. Sin eso, el endpoint de
ejecución devuelve qué haría, pero no lo ejecuta — así se cumple el
requisito del prompt de que la IA no sustituye el juicio humano en acciones
críticas. Las acciones en sí (notificar, abrir ticket, comprobación,
informe, escalar) están simuladas en el MVP: quedan registradas y devuelven
un resultado determinista, pero no hay todavía conectores reales a sistemas
externos (eso es fase 2/3, ver docs/ARQUITECTURA.md).
"""
from fastapi import APIRouter, Depends, HTTPException

from siem.models import AutomationRule
from siem.store import SiemStore, get_store

router = APIRouter(prefix="/v1/automation", tags=["automatizacion"])


@router.get("/rules", response_model=list[AutomationRule])
def list_rules(store: SiemStore = Depends(get_store)) -> list[AutomationRule]:
    return store.list_rules()


@router.post("/rules", response_model=AutomationRule)
def create_rule(rule: AutomationRule, store: SiemStore = Depends(get_store)) -> AutomationRule:
    return store.add_rule(rule)


@router.post("/rules/{rule_id}/execute")
def execute_rule(
    rule_id: str, confirm: bool = False, store: SiemStore = Depends(get_store)
) -> dict:
    rule = store.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Regla no encontrada")
    if not rule.enabled:
        raise HTTPException(status_code=400, detail="Regla deshabilitada")

    if rule.requires_confirmation and not confirm:
        return {
            "ejecutado": False,
            "motivo": "Esta acción requiere confirmación explícita del cliente.",
            "accion_propuesta": rule.action.value,
            "como_confirmar": f"POST /v1/automation/rules/{rule_id}/execute?confirm=true",
        }

    # Simulado a propósito — ver docstring del módulo.
    return {
        "ejecutado": True,
        "accion": rule.action.value,
        "resultado": f"Acción '{rule.action.value}' simulada correctamente para la regla '{rule.name}'.",
    }
