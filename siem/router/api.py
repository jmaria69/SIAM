from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from typing import Dict, Any, List
import os
from ..config import settings
from ..models import SiemTicket
from ..jira_to_siem_mapper import map_jira_to_siem
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..db_models import Ticket
from ..database import get_db

router = APIRouter()

# Persistencia en base de datos SQLite (SQLAlchemy)
# Se usa Session dependency en cada endpoint


# CORS origins are handled in main app

@router.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """El widget viejo (index.html, JS plano, solo tickets Jira) ya no se
    sirve aquí — José pidió quitarlo. "/" muestra ahora el SOC nuevo
    directamente. No se pudo borrar index.html del disco en esta sesión (el
    sandbox de comandos seguía roto), pero al no estar enrutado en ningún
    sitio queda inalcanzable desde la app igualmente."""
    if os.path.exists("soc_dashboard.html"):
        with open("soc_dashboard.html", "r", encoding="utf-8") as f:
            # no-store: el dashboard se edita en caliente (volumen montado) y un
            # HTML cacheado por el navegador ya nos costó un debug de responsive.
            return HTMLResponse(f.read(), headers={"Cache-Control": "no-store"})
    return "<h1>soc_dashboard.html no encontrado</h1>"

@router.get("/dashboard", response_class=HTMLResponse)
async def get_soc_dashboard_alias():
    """Alias de compatibilidad — el SOC ahora vive en "/"."""
    return RedirectResponse(url="/")

@router.get("/health")
async def health_check():
    return {"status": "healthy", "orchestrator": "active"}

@router.post("/v1/ingest/jira", response_model=SiemTicket)
async def ingest_jira_webhook(payload: Dict[Any, Any], db: Session = Depends(get_db)):
    """Recibe un payload que puede ser:
    * El formato JIRA (dict con clave "issue"), que se mapea a SiemTicket mediante `map_jira_to_siem`.
    * Un objeto ya en formato SiemTicket JSON enviado por el frontend.
    La función persiste el ticket en SQLite y devuelve el modelo SiemTicket.
    """
    if not payload:
        raise HTTPException(status_code=400, detail="Payload vacío")
    try:
        # Determinar el tipo de payload
        if isinstance(payload, dict) and "issue" in payload:
            normalized = map_jira_to_siem(payload)
        else:
            # Asumir que ya es un SiemTicket válido
            normalized = SiemTicket.parse_obj(payload)
        db_ticket = Ticket(
            ticket_id=normalized.ticket_id,
            status=normalized.status,
            service=normalized.service,
            description=normalized.description,
            priority=normalized.priority,
        )
        db.add(db_ticket)
        db.commit()
        db.refresh(db_ticket)
        return normalized
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/v1/metrics")
async def get_siem_metrics(db: Session = Depends(get_db)):
    total = db.query(Ticket).count()
    status_counts = db.query(Ticket.status, func.count()).group_by(Ticket.status).all()
    distribution = {status: count for status, count in status_counts}
    recent = db.query(Ticket).order_by(Ticket.id.desc()).limit(5).all()
    critical_alerts = (
        db.query(Ticket)
        .filter(Ticket.priority.in_(["HIGH", "ALTA", "CRITICAL", "CRITICA", "critical"]))
        .count()
    )
    # El dashboard React (src/components/SiemCrmDashboard.jsx) espera
    # external_id/provider/summary además de los campos de SiemTicket —
    # antes no existían en la respuesta y esas columnas salían vacías.
    recent_list = [
        {
            **SiemTicket(
                ticket_id=t.ticket_id,
                status=t.status,
                service=t.service,
                description=t.description,
                priority=t.priority,
            ).dict(),
            "external_id": t.ticket_id,
            "provider": t.service,
            "summary": t.description or t.ticket_id,
        }
        for t in recent
    ]
    return {
        "summary": {
            "total_tickets": total,
            "status_distribution": distribution,
            "critical_alerts": critical_alerts,
            "olga_auto_recovery_rate": "100%" if total > 0 else "0%",
        },
        "recent_tickets": recent_list,
    }

@router.get("/v1/tickets", response_model=List[SiemTicket])
async def list_tickets(db: Session = Depends(get_db)):
    tickets = db.query(Ticket).all()
    return [
        SiemTicket(
            ticket_id=t.ticket_id,
            status=t.status,
            service=t.service,
            description=t.description,
            priority=t.priority,
        )
        for t in tickets
    ]
