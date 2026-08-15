"""Tests de integración para los endpoints /v1/pyme/* (Ciberseguridad PYME).

Cubre los 5 bloques del módulo basado en las 18 Unidades Didácticas:
1. Plan Director de Seguridad (PDS)
2. Matriz de Riesgos y BIA
3. Calculadora de Backup 3-2-1 y DRP
4. Simulador de Ataques (9 vectores)
5. Auditoría ISO 27001 / RGPD (15 controles)
"""

import pytest
from fastapi.testclient import TestClient
from siem.main import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


# ---------------------------------------------------------------------------
# Plan Director de Seguridad (PDS)
# ---------------------------------------------------------------------------

def test_pds_template_returns_example(client):
    resp = client.get("/v1/pyme/pds/template")
    assert resp.status_code == 200
    data = resp.json()
    assert "empresa_nombre" in data
    assert "sector" in data


def test_pds_generate_returns_full_plan(client):
    resp = client.post("/v1/pyme/pds/generate", json={
        "empresa_nombre": "TestCorp PYME S.L.",
        "sector": "E-Commerce",
        "num_empleados": 15,
        "tiene_ecommerce": True,
        "tiene_teletrabajo": True,
        "usa_nube": True,
        "usa_iot": False,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["empresa"] == "TestCorp PYME S.L."
    assert "fases_ciclo_pdca" in data
    politicas = data["politicas_por_componente"]
    assert "recursos_humanos" in politicas
    assert "recursos_tecnologicos" in politicas
    assert "recursos_organizativos" in politicas
    assert "recursos_fisicos" in politicas
    assert len(data["marcos_normativos"]) >= 4


def test_pds_with_iot_adds_iot_policy(client):
    resp = client.post("/v1/pyme/pds/generate", json={
        "empresa_nombre": "IoTCorp",
        "sector": "Industria 4.0",
        "num_empleados": 50,
        "tiene_ecommerce": False,
        "tiene_teletrabajo": False,
        "usa_nube": True,
        "usa_iot": True,
    })
    assert resp.status_code == 200
    tecnologica = resp.json()["politicas_por_componente"]["recursos_tecnologicos"]
    assert any("IoT" in p or "VLAN" in p for p in tecnologica)


# ---------------------------------------------------------------------------
# Matriz de Riesgos
# ---------------------------------------------------------------------------

def test_risk_critico_when_max_values(client):
    resp = client.post("/v1/pyme/risk-matrix/assess", json={
        "activo_nombre": "Base de Datos Produccion",
        "probabilidad": 5,
        "impacto": 5,
        "amenaza_tipo": "Ransomware",
        "estrategia_deseada": "mitigar",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["valor_riesgo_total"] == 25
    assert data["nivel_riesgo"] == "CRITICO"
    assert data["color_badge"] == "rose"


def test_risk_bajo_when_min_values(client):
    resp = client.post("/v1/pyme/risk-matrix/assess", json={
        "activo_nombre": "Impresora Oficina",
        "probabilidad": 1,
        "impacto": 1,
        "amenaza_tipo": "Acceso no autorizado",
        "estrategia_deseada": "aceptar",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["nivel_riesgo"] == "BAJO"
    assert data["color_badge"] == "emerald"


def test_risk_formula_is_p_times_i(client):
    resp = client.post("/v1/pyme/risk-matrix/assess", json={
        "activo_nombre": "Servidor Web",
        "probabilidad": 3,
        "impacto": 4,
        "amenaza_tipo": "DDoS",
        "estrategia_deseada": "mitigar",
    })
    assert resp.status_code == 200
    assert resp.json()["valor_riesgo_total"] == 12


# ---------------------------------------------------------------------------
# BIA
# ---------------------------------------------------------------------------

def test_bia_sensitive_data_gives_strict_rto(client):
    resp = client.post("/v1/pyme/bia/assess", json={
        "servicio_critico": "Plataforma E-Commerce",
        "impacto_financiero_hora": 2000.0,
        "datos_sensibles": True,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "2.0 horas" in data["indicadores_continuidad"]["RTO_tiempo_maximo_tolerable_recuperacion"]
    assert "48000" in data["impacto_economico_estimado"]["coste_parada_24h"]


def test_bia_non_sensitive_gives_relaxed_rto(client):
    resp = client.post("/v1/pyme/bia/assess", json={
        "servicio_critico": "Portal de Noticias Interno",
        "impacto_financiero_hora": 100.0,
        "datos_sensibles": False,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "8.0 horas" in data["indicadores_continuidad"]["RTO_tiempo_maximo_tolerable_recuperacion"]


# ---------------------------------------------------------------------------
# Backup y DRP
# ---------------------------------------------------------------------------

def test_backup_321_compliant(client):
    resp = client.post("/v1/pyme/drp/calculate", json={
        "volumen_datos_gb": 200.0,
        "metodo_backup": "incremental",
        "copias_fuera_sitio": 1,
        "soportes_diferentes": 2,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["regla_321"]["cumple"] is True
    assert "VALIDA" in data["regla_321"]["evaluacion"]


def test_backup_321_non_compliant(client):
    resp = client.post("/v1/pyme/drp/calculate", json={
        "volumen_datos_gb": 100.0,
        "metodo_backup": "full",
        "copias_fuera_sitio": 0,
        "soportes_diferentes": 1,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["regla_321"]["cumple"] is False
    assert "ADVERTENCIA" in data["regla_321"]["evaluacion"]


def test_backup_methods_are_explained(client):
    for method in ["full", "incremental", "diferencial", "mirror", "cdp"]:
        resp = client.post("/v1/pyme/drp/calculate", json={
            "volumen_datos_gb": 50.0,
            "metodo_backup": method,
            "copias_fuera_sitio": 1,
            "soportes_diferentes": 2,
        })
        assert resp.status_code == 200
        assert len(resp.json()["explicacion_metodo"]) > 10


# ---------------------------------------------------------------------------
# Simulador de Ataques
# ---------------------------------------------------------------------------

def test_simulation_vectors_list(client):
    resp = client.get("/v1/pyme/simulation/vectors")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["vectores"]) == 9
    assert len(data["defensas_disponibles"]) >= 8


def test_simulation_attack_blocked_by_correct_defense(client):
    # WAF bloquea SQLi
    resp = client.post("/v1/pyme/simulation/attack", json={
        "vector_ataque": "sqli_waf",
        "tecnologia_defensa": "waf",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["resultado_simulacion"]["bloqueado"] is True
    assert "BLOQUEADO" in data["resultado_simulacion"]["mensaje"]


def test_simulation_attack_fails_with_wrong_defense(client):
    # MFA no bloquea SQLi
    resp = client.post("/v1/pyme/simulation/attack", json={
        "vector_ataque": "sqli_waf",
        "tecnologia_defensa": "mfa",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["resultado_simulacion"]["bloqueado"] is False
    assert "EXITOSO" in data["resultado_simulacion"]["mensaje"]


def test_simulation_ransomware_blocked_by_backup_321(client):
    resp = client.post("/v1/pyme/simulation/attack", json={
        "vector_ataque": "ransomware_exfil",
        "tecnologia_defensa": "backup_321",
    })
    assert resp.status_code == 200
    assert resp.json()["resultado_simulacion"]["bloqueado"] is True


def test_simulation_phishing_blocked_by_mfa(client):
    resp = client.post("/v1/pyme/simulation/attack", json={
        "vector_ataque": "phishing_spear",
        "tecnologia_defensa": "mfa",
    })
    assert resp.status_code == 200
    assert resp.json()["resultado_simulacion"]["bloqueado"] is True


def test_simulation_unknown_vector_falls_back_to_sqli(client):
    resp = client.post("/v1/pyme/simulation/attack", json={
        "vector_ataque": "vector_inexistente",
        "tecnologia_defensa": "waf",
    })
    assert resp.status_code == 200
    # Debe devolver el fallback sqli_waf (waf lo bloquea)
    assert resp.json()["resultado_simulacion"]["bloqueado"] is True


# ---------------------------------------------------------------------------
# Auditoría ISO 27001 / RGPD
# ---------------------------------------------------------------------------

def test_audit_checklist_has_15_controls(client):
    resp = client.get("/v1/pyme/audit/checklist")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_controles"] == 15
    assert len(data["controles"]) == 15


def test_audit_all_controls_have_id_and_title(client):
    resp = client.get("/v1/pyme/audit/checklist")
    for control in resp.json()["controles"]:
        assert "id" in control
        assert "titulo" in control
        assert "categoria" in control


def test_audit_evaluate_100_percent(client):
    checklist = client.get("/v1/pyme/audit/checklist").json()["controles"]
    all_true = {c["id"]: True for c in checklist}
    resp = client.post("/v1/pyme/audit/evaluate", json={"respuestas": all_true})
    assert resp.status_code == 200
    data = resp.json()
    assert data["porcentaje_cumplimiento"] == 100.0
    assert data["color_badge"] == "emerald"
    assert data["cumplidos"] == 15


def test_audit_evaluate_0_percent(client):
    resp = client.post("/v1/pyme/audit/evaluate", json={"respuestas": {}})
    assert resp.status_code == 200
    data = resp.json()
    assert data["porcentaje_cumplimiento"] == 0.0
    assert data["color_badge"] == "rose"
    assert len(data["puntos_mejora_prioritarios"]) == 5


def test_audit_evaluate_partial_gives_amber(client):
    checklist = client.get("/v1/pyme/audit/checklist").json()["controles"]
    # 10 de 15 = 66.7% -> nivel INTERMEDIO
    partial = {c["id"]: True for c in checklist[:10]}
    resp = client.post("/v1/pyme/audit/evaluate", json={"respuestas": partial})
    assert resp.status_code == 200
    data = resp.json()
    assert data["color_badge"] == "amber"
    assert data["cumplidos"] == 10
