"""Expediente de Defensa (siem/evidence.py + siem/router/evidence.py).

Lo que se protege aquí es la propiedad que hace útil al módulo: que el
registro sea detectablemente inmutable y que el dossier NUNCA presente como
"probado" un control que solo está declarado. Si eso se rompe, el
expediente deja de servir para lo único que sirve -- responder un
cuestionario de ciberseguro sin mentir.
"""
from datetime import datetime, timedelta

from siem import evidence as evidence_module
from siem.config import Settings
from siem.models import Evidence, EvidenceKind, Event, Incident, Severity
from siem.response_actions import apply_response_action
from siem.store import SiemStore


def _store(db_session) -> SiemStore:
    return SiemStore(db_session)


def _record(store, **kwargs) -> Evidence:
    defaults = dict(kind=EvidenceKind.MANUAL, control_ids=["c4"], title="t", summary="s")
    defaults.update(kwargs)
    return evidence_module.record(store, Evidence(**defaults))


# ---------------------------------------------------------------------------
# Cadena de hashes
# ---------------------------------------------------------------------------

def test_ledger_vacio_es_integro(client):
    resp = client.get("/v1/evidence/verify")
    assert resp.status_code == 200
    assert resp.json()["integra"] is True
    assert resp.json()["total"] == 0


def test_cada_evidencia_enlaza_con_la_anterior(db_session):
    store = _store(db_session)
    primera = _record(store, title="primera")
    segunda = _record(store, title="segunda")

    # La génesis no tiene anterior; la siguiente apunta al hash de la génesis.
    assert primera.prev_hash is None
    assert segunda.prev_hash == primera.hash
    assert evidence_module.verify_chain(store)["integra"] is True


def test_modificar_una_fila_rompe_la_cadena(db_session):
    """El caso que da valor al módulo: alguien "mejora" el expediente por
    detrás con un UPDATE y el verificador lo delata."""
    from siem.db_models import EvidenceDB

    store = _store(db_session)
    _record(store, title="primera")
    manipulada = _record(store, title="segunda")
    _record(store, title="tercera")

    fila = db_session.query(EvidenceDB).filter(EvidenceDB.id == manipulada.id).first()
    fila.summary = "resumen retocado a posteriori"
    db_session.commit()

    resultado = evidence_module.verify_chain(store)
    assert resultado["integra"] is False
    assert resultado["motivo"] == "hash_alterado"
    assert resultado["rota_en"] == manipulada.id


def test_borrar_una_fila_intermedia_rompe_la_cadena(db_session):
    from siem.db_models import EvidenceDB

    store = _store(db_session)
    _record(store, title="primera")
    borrada = _record(store, title="segunda")
    tercera = _record(store, title="tercera")

    db_session.query(EvidenceDB).filter(EvidenceDB.id == borrada.id).delete()
    db_session.commit()

    resultado = evidence_module.verify_chain(store)
    assert resultado["integra"] is False
    assert resultado["motivo"] == "cadena_rota"
    assert resultado["rota_en"] == tercera.id


# ---------------------------------------------------------------------------
# Hooks: los hechos que antes se perdían
# ---------------------------------------------------------------------------

def test_accion_de_respuesta_deja_evidencia_fechada(db_session):
    """Un IOC dice que la IP ESTÁ bloqueada ahora y desaparece al
    desbloquear; la evidencia dice que se bloqueó, y eso es lo que se
    presenta meses después."""
    store = _store(db_session)
    apply_response_action("203.0.113.9", "BLOCK", store, Settings(CLOUDFLARE_API_TOKEN=None))

    registros = store.list_evidence(limit=None)
    assert len(registros) == 1
    assert registros[0].kind == EvidenceKind.RESPUESTA_ACTIVA
    assert "c9" in registros[0].control_ids
    assert registros[0].payload["ip"] == "203.0.113.9"
    # Sin credenciales de Cloudflare la acción es simulada: el expediente lo
    # deja anotado para que nunca se presente como prueba de un bloqueo real.
    assert registros[0].payload["real"] is False


def test_honeypot_acredita_el_control_de_deteccion_temprana(db_session):
    store = _store(db_session)
    apply_response_action("203.0.113.10", "HONEYPOT", store, Settings(CLOUDFLARE_API_TOKEN=None))

    registros = store.list_evidence(limit=None)
    assert "s3" in registros[0].control_ids


def test_resolver_un_incidente_deja_evidencia_una_sola_vez(client, db_session):
    store = _store(db_session)
    incidente = store.add_incident(Incident(title="Fuerza bruta en el panel", severity=Severity.HIGH))

    primera = client.patch(f"/v1/incidents/{incidente.id}", json={"status": "resuelto"})
    assert primera.status_code == 200
    # Re-marcar resuelto algo ya resuelto NO debe duplicar la evidencia: si
    # no, el tiempo medio de contención del dossier dejaría de ser creíble.
    client.patch(f"/v1/incidents/{incidente.id}", json={"status": "resuelto"})

    contenidos = store.list_evidence(kind=EvidenceKind.INCIDENTE_CONTENIDO.value, limit=None)
    assert len(contenidos) == 1
    assert contenidos[0].source_ref == incidente.id


def test_autoevaluacion_registra_los_controles_declarados(client, db_session):
    resp = client.post("/v1/pyme/audit/evaluate", json={"respuestas": {"c4": True, "c10": False}})
    assert resp.status_code == 200

    registros = _store(db_session).list_evidence(kind=EvidenceKind.AUTOEVALUACION.value, limit=None)
    assert len(registros) == 1
    assert registros[0].control_ids == ["c4"]  # solo lo marcado como cumplido


# ---------------------------------------------------------------------------
# Dossier: probado vs declarado vs sin evidencia
# ---------------------------------------------------------------------------

def _controles(data) -> dict:
    return {c["id"]: c for c in data["controles"]}


def test_sin_nada_ningun_control_se_da_por_probado(client):
    data = client.get("/v1/evidence/dossier").json()
    assert data["resumen"]["probados"] == 0
    assert all(c["estado"] == "sin_evidencia" for c in data["controles"])
    # Y la respuesta sugerida desaconseja explícitamente decir que sí.
    assert "No responda" in data["controles"][0]["respuesta_sugerida"]
    assert data["controles"][0]["pendiente"]


def test_telemetria_del_waf_prueba_el_control_c9(client, db_session):
    store = _store(db_session)
    store.add_event(Event(source="waf-cloudflare", severity=Severity.HIGH, summary="SQLi bloqueada",
                          raw_payload={"client_ip": "203.0.113.5", "attack_category": "sqli"}))

    c9 = _controles(client.get("/v1/evidence/dossier").json())["c9"]
    assert c9["estado"] == "probado"
    assert c9["prueba"] == "operativa"
    assert c9["respuesta_sugerida"].startswith("Sí —")
    assert "1 ataque(s)" in c9["metrica"]


def test_evidencia_manual_deja_el_control_en_declarado_nunca_en_probado(client):
    """El control con más peso en la prima (MFA) no es observable por SIAM:
    aportar la captura debe subirlo a 'declarado', jamás a 'probado'."""
    creada = client.post("/v1/evidence/record", json={
        "control_ids": ["c4"], "title": "Captura de M365 con MFA obligatorio",
        "summary": "Política de acceso condicional activa para todos los usuarios",
    })
    assert creada.status_code == 201

    c4 = _controles(client.get("/v1/evidence/dossier").json())["c4"]
    assert c4["estado"] == "declarado"
    assert c4["prueba"] == "documental"
    assert "SIN prueba operativa" in c4["respuesta_sugerida"]
    assert c4["total_evidencias"] == 1


def test_evidencia_manual_rechaza_controles_inventados(client):
    resp = client.post("/v1/evidence/record", json={"control_ids": ["c99"], "title": "x"})
    assert resp.status_code == 422
    assert "c99" in resp.json()["detail"]


def test_el_dossier_respeta_el_periodo_pedido(client, db_session):
    store = _store(db_session)
    antigua = Evidence(kind=EvidenceKind.MANUAL, control_ids=["c4"], title="vieja",
                       recorded_at=datetime.utcnow() - timedelta(days=400))
    evidence_module.record(store, antigua)

    # Ventana por defecto (12 meses): la evidencia de hace 400 días queda fuera.
    assert _controles(client.get("/v1/evidence/dossier").json())["c4"]["estado"] == "sin_evidencia"

    desde = (datetime.utcnow() - timedelta(days=500)).strftime("%Y-%m-%d")
    ampliado = client.get(f"/v1/evidence/dossier?date_from={desde}").json()
    assert _controles(ampliado)["c4"]["estado"] == "declarado"


def test_dossier_html_se_genera_y_avisa_de_la_integridad(client, db_session):
    _record(_store(db_session), title="Prueba de restauración de backup", control_ids=["c11"])

    resp = client.get("/v1/evidence/dossier.html?empresa=TechSolutions+PYME+S.L.")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    cuerpo = resp.text
    assert "TechSolutions PYME S.L." in cuerpo
    assert "Cadena íntegra: 1 evidencia(s) verificadas." in cuerpo
    assert "DECLARADO" in cuerpo and "SIN EVIDENCIA" in cuerpo


def test_dossier_html_escapa_el_nombre_de_empresa(client):
    resp = client.get("/v1/evidence/dossier.html?empresa=<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text
