"""Tests de campañas de concienciación (siem/router/campaigns.py).

SMTP y proveedor de IA están forzados a "apagado" para todos los tests vía
el override de `get_settings` en conftest.py -- así que aquí se puede
asumir siempre `smtp_configurado: False` y contenido generado por
RuleBasedProvider, sin depender de credenciales reales ni de red.
"""


def _create_campaign(client, **overrides):
    payload = {
        "name": "Campaña de phishing Q3",
        "topic": "phishing",
        "content_type": "email_phishing",
        "targets": [
            {"name": "Ana Pérez", "email": "ana@empresa.com", "department": "Finanzas"},
            {"name": "Luis Gómez", "email": "luis@empresa.com", "department": "IT"},
            {"name": "Sin email", "email": None, "department": "Ventas"},
        ],
    }
    payload.update(overrides)
    return client.post("/v1/campaigns", json=payload)


def test_create_and_list_campaign(client):
    response = _create_campaign(client)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "borrador"
    assert len(data["targets"]) == 3
    assert all(t["id"] for t in data["targets"])  # ids generados al parsear

    listed = client.get("/v1/campaigns").json()
    assert len(listed) == 1
    assert listed[0]["id"] == data["id"]


def test_generate_content_without_ai_key_uses_rule_based_provider(client):
    campaign = _create_campaign(client).json()
    response = client.post(f"/v1/campaigns/{campaign['id']}/generate-content")
    assert response.status_code == 200
    body = response.json()
    assert "reglas" in body["proveedor_ia"]
    assert "SIMULACRO DE PHISHING" in body["content"]

    refreshed = client.get(f"/v1/campaigns/{campaign['id']}").json()
    assert refreshed["content"] == body["content"]


def test_send_without_content_returns_400(client):
    campaign = _create_campaign(client).json()
    response = client.post(f"/v1/campaigns/{campaign['id']}/send")
    assert response.status_code == 400


def test_send_without_smtp_configured_marks_all_omitted(client):
    campaign = _create_campaign(client).json()
    client.post(f"/v1/campaigns/{campaign['id']}/generate-content")
    response = client.post(f"/v1/campaigns/{campaign['id']}/send")
    assert response.status_code == 200
    data = response.json()
    assert data["smtp_configurado"] is False
    assert data["enviados"] == 0
    # 2 destinatarios con email (se intentan y se omiten por falta de SMTP)
    # + 1 sin email (se omite directamente) = 3 omitidos.
    assert data["omitidos"] == 3
    assert data["aviso"] is not None

    campaign_after = client.get(f"/v1/campaigns/{campaign['id']}").json()
    assert campaign_after["status"] == "activa"


def test_click_marks_target_and_returns_html_page(client):
    campaign = _create_campaign(client).json()
    target_id = campaign["targets"][0]["id"]

    response = client.get(f"/v1/campaigns/{campaign['id']}/click/{target_id}")
    assert response.status_code == 200
    assert "simulacro" in response.text.lower()

    updated = client.get(f"/v1/campaigns/{campaign['id']}").json()
    target = next(t for t in updated["targets"] if t["id"] == target_id)
    assert target["status"] == "clic"
    assert target["clicked_at"] is not None


def test_report_marks_target(client):
    campaign = _create_campaign(client).json()
    target_id = campaign["targets"][0]["id"]

    response = client.get(f"/v1/campaigns/{campaign['id']}/report/{target_id}")
    assert response.status_code == 200

    updated = client.get(f"/v1/campaigns/{campaign['id']}").json()
    target = next(t for t in updated["targets"] if t["id"] == target_id)
    assert target["status"] == "reportado"
    assert target["reported_at"] is not None


def test_validate_before_acknowledge_returns_400(client):
    campaign = _create_campaign(client).json()
    target_id = campaign["targets"][0]["id"]

    response = client.post(
        f"/v1/campaigns/{campaign['id']}/targets/{target_id}/validate",
        json={"validated_by": "responsable_seguridad"},
    )
    assert response.status_code == 400


def test_acknowledge_then_validate_workflow(client):
    campaign = _create_campaign(client).json()
    target_id = campaign["targets"][0]["id"]

    ack = client.get(f"/v1/campaigns/{campaign['id']}/targets/{target_id}/acknowledge")
    assert ack.status_code == 200

    after_ack = client.get(f"/v1/campaigns/{campaign['id']}").json()
    target = next(t for t in after_ack["targets"] if t["id"] == target_id)
    assert target["status"] == "completado"
    assert target["acknowledged_at"] is not None
    assert target["validated_by_security"] is False

    validate = client.post(
        f"/v1/campaigns/{campaign['id']}/targets/{target_id}/validate",
        json={"validated_by": "responsable_seguridad"},
    )
    assert validate.status_code == 200
    validated_target = next(t for t in validate.json()["targets"] if t["id"] == target_id)
    assert validated_target["status"] == "validado"
    assert validated_target["validated_by_security"] is True
    assert validated_target["validated_by"] == "responsable_seguridad"


def test_campaign_metrics_reflects_target_states(client):
    campaign = _create_campaign(client).json()
    targets = campaign["targets"]

    client.get(f"/v1/campaigns/{campaign['id']}/click/{targets[0]['id']}")
    client.get(f"/v1/campaigns/{campaign['id']}/report/{targets[1]['id']}")
    client.get(f"/v1/campaigns/{campaign['id']}/targets/{targets[2]['id']}/acknowledge")

    metrics = client.get(f"/v1/campaigns/{campaign['id']}/metrics").json()
    assert metrics["total_destinatarios"] == 3
    assert metrics["clics"] == 1
    assert metrics["reportados"] == 1
    assert metrics["completados"] == 1
    assert metrics["validados"] == 0
    assert "Finanzas" in metrics["por_departamento"]


def test_unknown_campaign_returns_404(client):
    assert client.get("/v1/campaigns/CAMP-doesnotexist").status_code == 404
    assert client.post("/v1/campaigns/CAMP-doesnotexist/generate-content").status_code == 404
    assert client.post("/v1/campaigns/CAMP-doesnotexist/send").status_code == 404


def test_delete_campaign_removes_it(client):
    campaign_id = _create_campaign(client).json()["id"]
    assert client.get(f"/v1/campaigns/{campaign_id}").status_code == 200

    response = client.delete(f"/v1/campaigns/{campaign_id}")
    assert response.status_code == 200
    assert response.json() == {"campaign_id": campaign_id, "borrada": True}

    assert client.get(f"/v1/campaigns/{campaign_id}").status_code == 404
    assert client.get("/v1/campaigns").json() == []


def test_delete_unknown_campaign_returns_404(client):
    assert client.delete("/v1/campaigns/CAMP-doesnotexist").status_code == 404


# ---------------------------------------------------------------------------
# Analítica cruzada entre campañas (2026-07-03): tendencia de tasa de clic
# a lo largo de varias campañas, comparativa por departamento acumulada, y
# reincidentes (quién hace clic en más de una campaña -- el dato que
# diferencia esto de un SOC de correlación de eventos genérico).
#
# Se registra `GET /analytics` ANTES de `GET /{campaign_id}` en
# campaigns.py a propósito: si fuera al revés, una petición a
# /v1/campaigns/analytics coincidiría con el patrón `/{campaign_id}` (un
# único segmento) antes de llegar a la ruta real. El último test de este
# bloque cubre justo eso.
# ---------------------------------------------------------------------------
def test_analytics_excludes_draft_campaigns(client):
    _create_campaign(client, name="Borrador sin enviar")
    data = client.get("/v1/campaigns/analytics").json()
    assert data == {"total_campanas": 0, "tendencia": [], "por_departamento": {}, "reincidentes": []}


def test_analytics_tracks_repeat_clickers_across_campaigns(client):
    targets = [
        {"name": "Ana Pérez", "email": "ana@empresa.com", "department": "finanzas"},
        {"name": "Luis Gómez", "email": "luis@empresa.com", "department": "it"},
    ]
    c1 = _create_campaign(client, name="Campaña 1", targets=targets).json()["id"]
    c2 = _create_campaign(client, name="Campaña 2", targets=targets).json()["id"]

    for cid in (c1, c2):
        client.post(f"/v1/campaigns/{cid}/generate-content")
        client.post(f"/v1/campaigns/{cid}/send")
        campaign = client.get(f"/v1/campaigns/{cid}").json()
        ana_id = next(t["id"] for t in campaign["targets"] if t["email"] == "ana@empresa.com")
        client.get(f"/v1/campaigns/{cid}/click/{ana_id}")
        # Luis no hace clic en ninguna campaña -- no debe salir en reincidentes.

    data = client.get("/v1/campaigns/analytics").json()
    assert data["total_campanas"] == 2
    assert [t["name"] for t in data["tendencia"]] == ["Campaña 1", "Campaña 2"]
    assert all(t["tasa_clic"] == 50.0 for t in data["tendencia"])

    assert len(data["reincidentes"]) == 1
    reincidente = data["reincidentes"][0]
    assert reincidente["email"] == "ana@empresa.com"
    assert reincidente["clics"] == 2
    assert reincidente["campanas_recibidas"] == 2
    assert reincidente["campanas_con_clic"] == ["Campaña 1", "Campaña 2"]

    assert data["por_departamento"]["finanzas"]["tasa_clic"] == 100.0
    assert data["por_departamento"]["it"]["tasa_clic"] == 0.0


def test_analytics_route_does_not_collide_with_campaign_id_route(client):
    resp = client.get("/v1/campaigns/analytics")
    assert resp.status_code == 200
    assert "total_campanas" in resp.json()
