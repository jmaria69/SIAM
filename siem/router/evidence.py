"""Expediente de Defensa (ver siem/evidence.py): consulta del ledger,
verificación de la cadena y generación del dossier de cumplimiento.

Vive bajo /v1/ a propósito: el expediente contiene el inventario de lo que
la pyme NO cumple, que es justo lo que no puede quedar expuesto sin sesión
ni API key (el middleware de siem/main.py ya cubre todo /v1/*).
"""
from __future__ import annotations

import html
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse

from siem import evidence as evidence_module
from siem.models import Evidence, EvidenceCreate, EvidenceKind
from siem.store import SiemStore, get_store

router = APIRouter(prefix="/v1/evidence", tags=["expediente"])

# Ventana por defecto del dossier: 12 meses. Es el periodo que cubre una
# solicitud/renovación de póliza y el que un auditor NIS2 da por supuesto
# cuando pide "el último ejercicio".
DEFAULT_PERIOD_DAYS = 365


def _parse_period(date_from: Optional[str], date_to: Optional[str]) -> tuple[datetime, datetime]:
    """Mismo criterio de fechas que siem/router/active_defense.py: ISO
    YYYY-MM-DD, `date_to` inclusivo hasta el final del día (si no, pedir
    hasta hoy dejaría fuera todo lo de hoy)."""
    try:
        hasta = (
            datetime.fromisoformat(date_to).replace(hour=23, minute=59, second=59)
            if date_to else datetime.utcnow()
        )
        desde = (
            datetime.fromisoformat(date_from)
            if date_from else hasta - timedelta(days=DEFAULT_PERIOD_DAYS)
        )
    except ValueError:
        raise HTTPException(status_code=422, detail="Fechas en formato ISO (YYYY-MM-DD).")
    if desde > hasta:
        raise HTTPException(status_code=422, detail="La fecha inicial es posterior a la final.")
    return desde, hasta


@router.get("/ledger", response_model=list[Evidence])
def list_ledger(
    kind: Optional[EvidenceKind] = None,
    control_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = Query(500, ge=1, le=5000),
    store: SiemStore = Depends(get_store),
) -> list[Evidence]:
    """El registro completo, en orden de la cadena (ASC)."""
    desde, hasta = _parse_period(date_from, date_to) if (date_from or date_to) else (None, None)
    return store.list_evidence(
        kind=kind.value if kind else None, control_id=control_id,
        date_from=desde, date_to=hasta, limit=limit,
    )


@router.get("/verify")
def verify(store: SiemStore = Depends(get_store)) -> dict:
    """Integridad de la cadena. Es el endpoint que un auditor ejecuta
    delante del cliente: si devuelve `integra: false`, el expediente entero
    deja de valer como prueba a partir del punto de ruptura."""
    return evidence_module.verify_chain(store)


@router.post("/record", response_model=Evidence, status_code=201)
def record_manual(entry: EvidenceCreate, store: SiemStore = Depends(get_store)) -> Evidence:
    """Aporta una evidencia externa (captura del MFA en M365, informe de
    restauración del proveedor...). Entra al mismo ledger encadenado pero
    como MANUAL, que queda fuera de OPERATIONAL_KINDS: sirve para pasar un
    control de `sin_evidencia` a `declarado`, nunca a `probado`."""
    desconocidos = [c for c in entry.control_ids if c not in evidence_module.CONTROLS]
    if desconocidos:
        raise HTTPException(
            status_code=422,
            detail=f"Controles no reconocidos: {', '.join(desconocidos)}. Ver GET /v1/evidence/controls.",
        )
    return evidence_module.record(store, Evidence(
        kind=EvidenceKind.MANUAL,
        control_ids=entry.control_ids,
        title=entry.title,
        summary=entry.summary,
        payload=entry.payload,
        actor=entry.actor,
    ))


@router.get("/controls")
def list_controls() -> list[dict]:
    """Catálogo de controles del expediente, en orden de presentación."""
    return [
        {
            "id": c.id, "categoria": c.categoria, "titulo": c.titulo,
            "pregunta_aseguradora": c.pregunta_aseguradora, "referencia": c.referencia,
            "evidencia_operativa": c.evidencia_operativa,
        }
        for c in (evidence_module.CONTROLS[cid] for cid in evidence_module.CONTROL_ORDER)
    ]


@router.get("/dossier")
def dossier(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    store: SiemStore = Depends(get_store),
) -> dict:
    desde, hasta = _parse_period(date_from, date_to)
    return evidence_module.build_dossier(store, date_from=desde, date_to=hasta)


ESTADO_ETIQUETA = {
    "probado": ("PROBADO", "probado"),
    "declarado": ("DECLARADO", "declarado"),
    "sin_evidencia": ("SIN EVIDENCIA", "sin-evidencia"),
}


@router.get("/dossier.html", response_class=HTMLResponse)
def dossier_html(
    empresa: str = Query("", max_length=160),
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    store: SiemStore = Depends(get_store),
) -> str:
    """El expediente como documento imprimible (Ctrl+P -> Guardar como PDF).

    Sin librería de PDF a propósito: añadir WeasyPrint/ReportLab arrastra
    dependencias de sistema (cairo, pango) al Dockerfile para producir lo
    mismo que el diálogo de impresión del navegador. Si algún día hace falta
    generarlo sin humano delante (envío programado al corredor), entonces sí
    vale la pena, y este HTML ya sirve de plantilla.
    """
    desde, hasta = _parse_period(date_from, date_to)
    data = evidence_module.build_dossier(store, date_from=desde, date_to=hasta)
    e = html.escape
    periodo = f"{data['periodo']['desde']:%d/%m/%Y} — {data['periodo']['hasta']:%d/%m/%Y}"
    integridad = data["integridad"]

    filas = []
    for c in data["controles"]:
        etiqueta, css = ESTADO_ETIQUETA[c["estado"]]
        cuerpo = [
            f'<div class="pregunta">{e(c["pregunta_aseguradora"])}</div>',
            f'<div class="respuesta">{e(c["respuesta_sugerida"])}</div>',
        ]
        if c["pendiente"]:
            cuerpo.append(f'<div class="pendiente">Acción pendiente: {e(c["pendiente"])}</div>')
        if c["evidencias"]:
            refs = ", ".join(
                f'{e(ev["id"])} ({ev["fecha"]:%d/%m/%Y})' for ev in c["evidencias"]
            )
            extra = f" y {c['total_evidencias'] - len(c['evidencias'])} más" if c["total_evidencias"] > len(c["evidencias"]) else ""
            cuerpo.append(f'<div class="refs">Evidencias: {refs}{extra}</div>')
        filas.append(f"""
      <tr>
        <td class="ctrl"><strong>{e(c["id"]).upper()}</strong><br><span class="cat">{e(c["categoria"])}</span></td>
        <td>
          <div class="titulo">{e(c["titulo"])}</div>
          {"".join(cuerpo)}
          <div class="ref">{e(c["referencia"])}</div>
        </td>
        <td class="estado"><span class="badge {css}">{etiqueta}</span></td>
      </tr>""")

    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<title>Expediente de Defensa{" — " + e(empresa) if empresa else ""}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; color: #111827;
         max-width: 900px; margin: 0 auto; padding: 32px; line-height: 1.45; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .sub {{ color: #6b7280; font-size: 13px; margin-bottom: 20px; }}
  .cintillo {{ display: flex; gap: 12px; margin: 18px 0 24px; }}
  .kpi {{ flex: 1; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; }}
  .kpi b {{ display: block; font-size: 24px; }}
  .kpi span {{ font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  td {{ border-top: 1px solid #e5e7eb; padding: 12px 8px; vertical-align: top; }}
  .ctrl {{ width: 80px; color: #374151; }}
  .cat {{ font-size: 11px; color: #9ca3af; }}
  .titulo {{ font-weight: 600; margin-bottom: 6px; }}
  .pregunta {{ color: #4b5563; font-style: italic; margin-bottom: 6px; }}
  .respuesta {{ background: #f9fafb; border-left: 3px solid #d1d5db; padding: 8px 10px; margin-bottom: 6px; }}
  .pendiente {{ color: #b45309; font-size: 12px; margin-bottom: 6px; }}
  .refs, .ref {{ font-size: 11px; color: #9ca3af; }}
  .estado {{ width: 110px; text-align: right; }}
  .badge {{ font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 99px; white-space: nowrap; }}
  .probado {{ background: #d1fae5; color: #065f46; }}
  .declarado {{ background: #fef3c7; color: #92400e; }}
  .sin-evidencia {{ background: #fee2e2; color: #991b1b; }}
  .integridad {{ margin-top: 24px; padding: 12px; border-radius: 8px; font-size: 12px;
                 background: {"#f0fdf4" if integridad["integra"] else "#fef2f2"};
                 color: {"#166534" if integridad["integra"] else "#991b1b"}; }}
  .aviso {{ margin-top: 16px; font-size: 11px; color: #6b7280; border-top: 1px solid #e5e7eb; padding-top: 12px; }}
  @media print {{ body {{ padding: 0; }} tr {{ page-break-inside: avoid; }} }}
</style></head><body>
  <h1>Expediente de Defensa{" — " + e(empresa) if empresa else ""}</h1>
  <div class="sub">Periodo {periodo} · Generado el {data['generado_el']:%d/%m/%Y %H:%M} UTC por SIEM Security</div>
  <div class="cintillo">
    <div class="kpi"><b>{data['resumen']['probados']}</b><span>Probados con telemetría</span></div>
    <div class="kpi"><b>{data['resumen']['declarados']}</b><span>Solo declarados</span></div>
    <div class="kpi"><b>{data['resumen']['sin_evidencia']}</b><span>Sin evidencia</span></div>
    <div class="kpi"><b>{data['evidencias_en_periodo']}</b><span>Registros del periodo</span></div>
  </div>
  <table>{"".join(filas)}</table>
  <div class="integridad"><strong>Integridad del registro:</strong> {e(integridad['detalle'])}</div>
  <div class="aviso">
    Las respuestas sugeridas se derivan de la telemetría registrada por SIEM Security en el periodo indicado.
    Un control marcado como <strong>DECLARADO</strong> se apoya únicamente en documentación aportada, no en
    prueba de funcionamiento. Revise cada respuesta antes de trasladarla a una solicitud de seguro: una
    declaración materialmente inexacta puede dar lugar a la rescisión de la póliza.
  </div>
</body></html>"""
