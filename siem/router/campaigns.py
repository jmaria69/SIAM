"""Campañas de concienciación en seguridad (nuevo).

El vector de entrada más común en una pyme no es una vulnerabilidad de
software, es un empleado (phishing, ingeniería social, malas prácticas con
contraseñas o datos). Este router cubre el ciclo completo: crear una
campaña, generar su contenido con el motor de IA plegable ya existente,
enviarlo por email (SMTP opcional, se omite con gracia si no está
configurado — ver `siem/notifications.py`), trackear quién hizo clic en un
phishing simulado o lo reportó, y el flujo que pidió José explícitamente:
el empleado confirma que ha leído el contenido, y el equipo de seguridad
tiene que VALIDAR esa confirmación antes de darla por buena.

Los endpoints de clic/reporte/confirmación son GET y sin autenticación a
propósito: están pensados para ser un enlace dentro de un email, no una
llamada de API — es exactamente como funcionan las plataformas de phishing
simulado reales (KnowBe4, Proofpoint...).
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from siem.ai import get_ai_provider
from siem.config import Settings, get_settings
from siem.models import Campaign, CampaignContentType, CampaignStatus, TargetStatus
from siem.notifications import enviar_email
from siem.store import SiemStore, get_store

router = APIRouter(prefix="/v1/campaigns", tags=["campanas"])


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------
@router.get("", response_model=list[Campaign])
def list_campaigns(store: SiemStore = Depends(get_store)) -> list[Campaign]:
    return store.list_campaigns()


@router.post("", response_model=Campaign)
def create_campaign(campaign: Campaign, store: SiemStore = Depends(get_store)) -> Campaign:
    return store.add_campaign(campaign)


# ---------------------------------------------------------------------------
# Analítica cruzada entre campañas: el dato que diferencia esto de un SOC
# genérico no es más panel de correlación de eventos, es el histórico POR
# PERSONA a través de varias campañas -- quién repite haciendo clic en
# phishing simulado, y si la tasa de clic mejora campaña a campaña. Se
# registra ANTES de `GET /{campaign_id}` a propósito: si fuera al revés,
# una petición a /v1/campaigns/analytics coincidiría con el patrón
# `/{campaign_id}` (un único segmento) y FastAPI probaría a buscar una
# campaña con id "analytics" en vez de llegar aquí -- el orden de
# registro de rutas con el mismo "shape" importa.
# ---------------------------------------------------------------------------
@router.get("/analytics")
def campaigns_analytics(store: SiemStore = Depends(get_store)) -> dict:
    campaigns = [c for c in store.list_campaigns() if c.status != CampaignStatus.BORRADOR]

    def pct(n: int, total: int) -> float:
        return round(100 * n / total, 1) if total else 0.0

    tendencia: list[dict] = []
    por_departamento: dict[str, dict] = {}
    reincidentes: dict[str, dict] = {}

    for c in sorted(campaigns, key=lambda c: c.created_at):
        total = len(c.targets)
        clics = sum(1 for t in c.targets if t.clicked_at)
        reportados = sum(1 for t in c.targets if t.reported_at)
        validados = sum(1 for t in c.targets if t.validated_by_security)
        tendencia.append(
            {
                "campaign_id": c.id,
                "name": c.name,
                "created_at": c.created_at.isoformat(),
                "total_destinatarios": total,
                "tasa_clic": pct(clics, total),
                "tasa_reporte": pct(reportados, total),
                "tasa_validacion": pct(validados, total),
            }
        )

        for t in c.targets:
            dep = t.department or "sin_departamento"
            stats = por_departamento.setdefault(
                dep, {"total_destinatarios": 0, "clics": 0, "reportados": 0}
            )
            stats["total_destinatarios"] += 1
            if t.clicked_at:
                stats["clics"] += 1
            if t.reported_at:
                stats["reportados"] += 1

            if not t.email:
                continue
            persona = reincidentes.setdefault(
                t.email,
                {
                    "email": t.email,
                    "name": t.name,
                    "campanas_recibidas": 0,
                    "clics": 0,
                    "reportes": 0,
                    "campanas_con_clic": [],
                },
            )
            persona["campanas_recibidas"] += 1
            if t.clicked_at:
                persona["clics"] += 1
                persona["campanas_con_clic"].append(c.name)
            if t.reported_at:
                persona["reportes"] += 1

    for stats in por_departamento.values():
        stats["tasa_clic"] = pct(stats["clics"], stats["total_destinatarios"])
        stats["tasa_reporte"] = pct(stats["reportados"], stats["total_destinatarios"])

    reincidentes_list = sorted(
        (p for p in reincidentes.values() if p["clics"] > 0),
        key=lambda p: p["clics"],
        reverse=True,
    )

    return {
        "total_campanas": len(campaigns),
        "tendencia": tendencia,
        "por_departamento": por_departamento,
        "reincidentes": reincidentes_list,
    }


@router.get("/{campaign_id}", response_model=Campaign)
def get_campaign(campaign_id: str, store: SiemStore = Depends(get_store)) -> Campaign:
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    return campaign


@router.delete("/{campaign_id}")
def delete_campaign(campaign_id: str, store: SiemStore = Depends(get_store)) -> dict:
    # Sin restricción por estado a propósito: borrar una campaña activa o
    # finalizada es una decisión válida de José (limpiar pruebas, datos de
    # un cliente que ya no aplica...), no algo que el backend deba impedir.
    # El aviso de que se pierde el histórico de esa campaña (clics,
    # reportes, validaciones -- también de /v1/campaigns/analytics) vive
    # en la confirmación del propio dashboard, no aquí.
    borrada = store.delete_campaign(campaign_id)
    if not borrada:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    return {"campaign_id": campaign_id, "borrada": True}


class CampaignUpdate(BaseModel):
    status: Optional[CampaignStatus] = None
    content: Optional[str] = None


@router.patch("/{campaign_id}", response_model=Campaign)
def update_campaign(
    campaign_id: str, update: CampaignUpdate, store: SiemStore = Depends(get_store)
) -> Campaign:
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    if update.status:
        campaign.status = update.status
    if update.content is not None:
        campaign.content = update.content
    return store.update_campaign(campaign)


# ---------------------------------------------------------------------------
# Contenido generado con IA
# ---------------------------------------------------------------------------
@router.post("/{campaign_id}/generate-content")
def generate_content(
    campaign_id: str,
    store: SiemStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    provider = get_ai_provider(settings)
    departamentos = sorted({t.department for t in campaign.targets if t.department})
    content = provider.generate_campaign_content(
        topic=campaign.topic.value,
        content_type=campaign.content_type.value,
        audience_hint=", ".join(departamentos),
    )
    campaign.content = content
    store.update_campaign(campaign)
    return {"campaign_id": campaign_id, "proveedor_ia": provider.name, "content": content}


# ---------------------------------------------------------------------------
# Envío
# ---------------------------------------------------------------------------
def _build_email_body(campaign: Campaign, target, settings: Settings) -> str:
    base = settings.CAMPAIGN_BASE_URL.rstrip("/")
    content_html = (campaign.content or "").replace("\n", "<br>")
    if campaign.content_type == CampaignContentType.EMAIL_PHISHING:
        click_url = f"{base}/v1/campaigns/{campaign.id}/click/{target.id}"
        report_url = f"{base}/v1/campaigns/{campaign.id}/report/{target.id}"
        return (
            f"{content_html}<br><br>"
            f'<a href="{click_url}">[ENLACE_SIMULACRO]</a><br><br>'
            f'<small style="color:#666">¿Sospechas que esto es phishing? '
            f'<a href="{report_url}">Repórtalo aquí</a>.</small>'
        )
    ack_url = f"{base}/v1/campaigns/{campaign.id}/targets/{target.id}/acknowledge"
    return f'{content_html}<br><br><a href="{ack_url}">He leído y entendido este contenido</a>'


def send_campaign_now(campaign: Campaign, store: SiemStore, settings: Settings) -> dict:
    """Lógica real de envío -- compartida entre el botón manual
    (`POST /{campaign_id}/send`) y el scheduler automático de
    `siem/campaign_scheduler.py` para campañas con `starts_at` vencido.
    Asume que quien llama ya comprobó que `campaign.content` existe."""
    enviados, omitidos = 0, 0
    for target in campaign.targets:
        if not target.email:
            omitidos += 1
            continue
        cuerpo = _build_email_body(campaign, target, settings)
        ok = enviar_email(settings, target.email, f"[SIEM Security] {campaign.name}", cuerpo)
        if ok:
            target.sent_at = datetime.utcnow()
            if target.status == TargetStatus.PENDIENTE:
                target.status = TargetStatus.ENVIADO
            enviados += 1
        else:
            omitidos += 1

    campaign.status = CampaignStatus.ACTIVA
    store.update_campaign(campaign)
    smtp_configurado = bool(settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASSWORD)
    return {
        "campaign_id": campaign.id,
        "enviados": enviados,
        "omitidos": omitidos,
        "smtp_configurado": smtp_configurado,
        "aviso": None if smtp_configurado else (
            "SMTP no configurado en .env — no se envió ningún email de verdad. "
            "Configura SMTP_HOST/SMTP_USER/SMTP_PASSWORD para enviar de verdad."
        ),
    }


@router.post("/{campaign_id}/send")
def send_campaign(
    campaign_id: str,
    store: SiemStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
) -> dict:
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    if not campaign.content:
        raise HTTPException(
            status_code=400, detail="La campaña no tiene contenido todavía — genera el contenido primero."
        )
    return send_campaign_now(campaign, store, settings)


# ---------------------------------------------------------------------------
# Tracking (enlaces dentro del email — GET, sin autenticación, a propósito)
# ---------------------------------------------------------------------------
def _find_target(campaign: Campaign, target_id: str):
    target = next((t for t in campaign.targets if t.id == target_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Destinatario no encontrado")
    return target


_PAGE_STYLE = (
    "body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;"
    "display:flex;align-items:center;justify-content:center;min-height:100vh;"
    "margin:0;text-align:center;padding:2rem}.card{max-width:480px}"
)


@router.get("/{campaign_id}/click/{target_id}", response_class=HTMLResponse)
def track_click(campaign_id: str, target_id: str, store: SiemStore = Depends(get_store)) -> str:
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    target = _find_target(campaign, target_id)
    if not target.clicked_at:
        target.clicked_at = datetime.utcnow()
        target.status = TargetStatus.CLIC
        store.update_campaign(campaign)
    return (
        f"<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>"
        f"<title>Simulacro de phishing</title><style>{_PAGE_STYLE}</style></head><body>"
        f"<div class='card'><h1>⚠️ Esto era un simulacro</h1>"
        f"<p>Acabas de hacer clic en un email de phishing <strong>simulado</strong>, parte de la "
        f"campaña de concienciación «{campaign.name}» de tu empresa. No pasa nada — detectar esto "
        f"la próxima vez es justo el objetivo del ejercicio.</p>"
        f"<p style='color:#94a3b8;font-size:0.9rem'>Consejos: verifica siempre el remitente real, "
        f"desconfía de la urgencia, y si tienes dudas repórtalo al equipo de seguridad antes de "
        f"hacer clic.</p></div></body></html>"
    )


@router.get("/{campaign_id}/report/{target_id}", response_class=HTMLResponse)
def track_report(campaign_id: str, target_id: str, store: SiemStore = Depends(get_store)) -> str:
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    target = _find_target(campaign, target_id)
    target.reported_at = datetime.utcnow()
    target.status = TargetStatus.REPORTADO
    store.update_campaign(campaign)
    return (
        f"<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>"
        f"<title>Gracias por reportarlo</title><style>{_PAGE_STYLE}</style></head><body>"
        f"<div class='card'><h1>✅ Gracias por reportarlo</h1>"
        f"<p>Este era un simulacro — y reportarlo en vez de hacer clic es exactamente el "
        f"comportamiento correcto. Buen trabajo.</p></div></body></html>"
    )


@router.get("/{campaign_id}/targets/{target_id}/acknowledge", response_class=HTMLResponse)
def acknowledge_target(campaign_id: str, target_id: str, store: SiemStore = Depends(get_store)) -> str:
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    target = _find_target(campaign, target_id)
    target.acknowledged_at = datetime.utcnow()
    if target.status in (TargetStatus.PENDIENTE, TargetStatus.ENVIADO):
        target.status = TargetStatus.COMPLETADO
    store.update_campaign(campaign)
    return (
        f"<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>"
        f"<title>Confirmación registrada</title><style>{_PAGE_STYLE}</style></head><body>"
        f"<div class='card'><h1>✅ Registrado</h1>"
        f"<p>Gracias por confirmar que has leído «{campaign.name}». El equipo de seguridad "
        f"validará esta confirmación.</p></div></body></html>"
    )


# ---------------------------------------------------------------------------
# Validación por el equipo de seguridad (dashboard, no un enlace de email)
# ---------------------------------------------------------------------------
class ValidateRequest(BaseModel):
    validated_by: str


@router.post("/{campaign_id}/targets/{target_id}/validate", response_model=Campaign)
def validate_target(
    campaign_id: str,
    target_id: str,
    body: ValidateRequest,
    store: SiemStore = Depends(get_store),
) -> Campaign:
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")
    target = _find_target(campaign, target_id)
    if not target.acknowledged_at:
        raise HTTPException(
            status_code=400,
            detail="El destinatario todavía no ha confirmado la lectura — no se puede validar antes de eso.",
        )
    target.validated_by_security = True
    target.validated_by = body.validated_by
    target.validated_at = datetime.utcnow()
    target.status = TargetStatus.VALIDADO
    return store.update_campaign(campaign)


# ---------------------------------------------------------------------------
# Métricas
# ---------------------------------------------------------------------------
@router.get("/{campaign_id}/metrics")
def campaign_metrics(campaign_id: str, store: SiemStore = Depends(get_store)) -> dict:
    campaign = store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")

    targets = campaign.targets
    total = len(targets)

    def pct(n: int) -> float:
        return round(100 * n / total, 1) if total else 0.0

    enviados = sum(1 for t in targets if t.sent_at)
    clics = sum(1 for t in targets if t.clicked_at)
    reportados = sum(1 for t in targets if t.reported_at)
    completados = sum(1 for t in targets if t.acknowledged_at)
    validados = sum(1 for t in targets if t.validated_by_security)

    por_departamento: dict = {}
    for t in targets:
        dep = t.department or "sin_departamento"
        stats = por_departamento.setdefault(dep, {"total": 0, "completados": 0, "validados": 0})
        stats["total"] += 1
        if t.acknowledged_at:
            stats["completados"] += 1
        if t.validated_by_security:
            stats["validados"] += 1

    return {
        "campaign_id": campaign_id,
        "total_destinatarios": total,
        "enviados": enviados,
        "clics": clics,
        "tasa_clic": pct(clics),
        "reportados": reportados,
        "tasa_reporte": pct(reportados),
        "completados": completados,
        "tasa_completado": pct(completados),
        "validados": validados,
        "tasa_validacion": pct(validados),
        "por_departamento": por_departamento,
    }
