# OBSOLETO: este archivo es una versión antigua, previa a la reorganización
# en el paquete `siam/` (ver CLAUDE.md). Guarda tickets en memoria (se
# pierden al reiniciar) y usa un modelo ligeramente distinto al actual.
# Docker y el README ya no lo usan — el entrypoint real es `siam.main:app`
# (`uvicorn siam.main:app`). Se deja aquí sin borrar para no destruir
# código sin permiso explícito, pero no debería ejecutarse en producción.
# Ver docs/ARQUITECTURA.md, sección "Auditoría del estado real del repo".
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from typing import Dict, Any, List
import os
from jira_to_siam_mapper import map_jira_to_siam, SiamTicket
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # 1. Importa el middleware

app = FastAPI()

# 2. Configura los orígenes permitidos (puedes usar "*" para desarrollo local)
origins = [
    "http://localhost:3000",  # Puerto típico de desarrollo de Next.js
    "http://localhost:8000",  # Puerto de tu backend/HTML actual
    "*",                      # Permite cualquier origen de forma temporal en desarrollo
]

# 3. Añade el middleware a la aplicación
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Permite GET, POST, OPTIONS, etc.
    allow_headers=["*"],  # Permite todos los headers
)

TICKET_STORAGE: List[SiamTicket] = []

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>SIAM Backend Activo</h1><p>Archivo index.html no encontrado en el contenedor.</p>"

@app.get("/health")
def health_check():
    return {"status": "healthy", "orchestrator": "active"}

@app.post("/v1/ingest/jira", response_model=SiamTicket)
def ingest_jira_webhook(payload: Dict[Any, Any]):
    try:
        if not payload:
            raise HTTPException(status_code=400, detail="Payload vacio")
        normalized_ticket = map_jira_to_siam(payload)
        TICKET_STORAGE.append(normalized_ticket)
        return normalized_ticket
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/v1/metrics")
def get_siam_metrics():
    total = len(TICKET_STORAGE)
    nuevos = sum(1 for t in TICKET_STORAGE if t.status == "NUEVO")
    en_progreso = sum(1 for t in TICKET_STORAGE if t.status == "EN_PROGRESO")
    resueltos = sum(1 for t in TICKET_STORAGE if t.status == "RESUELTO")
    altas = sum(1 for t in TICKET_STORAGE if t.priority in ["HIGH", "ALTA", "CRITICAL"])
    
    return {
        "summary": {
            "total_tickets": total,
            "status_distribution": {
                "NUEVO": nuevos,
                "EN_PROGRESO": en_progreso,
                "RESUELTO": resueltos
            },
            "critical_alerts": altas,
            "olga_auto_recovery_rate": "100%" if total > 0 else "0%"
        },
        "recent_tickets": [t.dict() for t in TICKET_STORAGE[-5:]]
    }
