"""Router FastAPI para el módulo de Ciberseguridad PYME integrado.

Prefijo: /v1/pyme
Expone los 5 bloques operativos del Plan Director de Seguridad.
"""

from fastapi import APIRouter
from siem.course_cybersecurity import (
    CourseCybersecurityEngine,
    PdsRequest,
    RiskAssessmentRequest,
    BiaRequest,
    BackupCalculatorRequest,
    AttackSimulationRequest,
    AuditEvaluationRequest,
)

router = APIRouter(prefix="/v1/pyme", tags=["Ciberseguridad PYME"])


# ---------------------------------------------------------------------------
# Plan Director de Seguridad (PDS)
# ---------------------------------------------------------------------------

@router.get("/pds/template", summary="Plantilla de PDS para PYME")
async def pds_template():
    """Devuelve un ejemplo completo de los datos requeridos para generar un PDS."""
    return {
        "empresa_nombre": "TechSolutions PYME S.L.",
        "sector": "Comercio Electronico",
        "num_empleados": 18,
        "tiene_ecommerce": True,
        "tiene_teletrabajo": True,
        "usa_nube": True,
        "usa_iot": False,
    }


@router.post("/pds/generate", summary="Genera el Plan Director de Seguridad (PDS)")
async def pds_generate(req: PdsRequest):
    """Genera un PDS completo con politicas por componente y ciclo PDCA."""
    return CourseCybersecurityEngine.generate_pds(req)


# ---------------------------------------------------------------------------
# Matriz de Riesgos y BIA
# ---------------------------------------------------------------------------

@router.post("/risk-matrix/assess", summary="Evalua nivel de riesgo (R=PxI) y estrategia de tratamiento")
async def risk_assess(req: RiskAssessmentRequest):
    """Calcula el riesgo segun la formula R = Probabilidad x Impacto."""
    return CourseCybersecurityEngine.assess_risk(req)


@router.post("/bia/assess", summary="Analisis de Impacto en el Negocio (BIA) con metricas RTO/RPO")
async def bia_assess(req: BiaRequest):
    """Calcula indicadores BIA: RTO, RPO, MTTD y MTTR segun criticidad del servicio."""
    return CourseCybersecurityEngine.assess_bia(req)


# ---------------------------------------------------------------------------
# Backup y DRP
# ---------------------------------------------------------------------------

@router.post("/drp/calculate", summary="Calculadora de estrategia de Backup 3-2-1 y borrado seguro")
async def drp_calculate(req: BackupCalculatorRequest):
    """Evalua el cumplimiento de la regla 3-2-1, el metodo de backup y los protocolos de borrado seguro."""
    return CourseCybersecurityEngine.calculate_backup_drp(req)


# ---------------------------------------------------------------------------
# Simulador de Ataques
# ---------------------------------------------------------------------------

@router.get("/simulation/vectors", summary="Lista de vectores de ataque simulables")
async def simulation_vectors():
    """Devuelve los vectores de ataque disponibles para simular."""
    return {
        "vectores": [
            {"id": "arp_poisoning",    "label": "ARP Poisoning / MitM"},
            {"id": "ddos_syn_flood",   "label": "DDoS SYN Flood"},
            {"id": "phishing_spear",   "label": "Spear Phishing"},
            {"id": "sqli_waf",         "label": "Inyeccion SQL (SQLi)"},
            {"id": "wpa3_byod",        "label": "BYOD en Red Wi-Fi Corporativa"},
            {"id": "iot_botnet",       "label": "Compromiso IoT / Botnet"},
            {"id": "biometric_spoof",  "label": "Suplantacion Biometrica"},
            {"id": "ransomware_exfil", "label": "Ransomware / Doble Extorsion"},
            {"id": "session_hijacking","label": "Secuestro de Sesion (Cookie/JWT)"},
        ],
        "defensas_disponibles": [
            "waf", "mfa", "edr", "vpn", "ids_ips", "backup_321", "radius", "segmentacion"
        ],
    }


@router.post("/simulation/attack", summary="Simula un escenario de ataque y evalua la defensa seleccionada")
async def simulation_attack(req: AttackSimulationRequest):
    """Ejecuta la simulacion de un ataque y devuelve el resultado segun la defensa aplicada."""
    return CourseCybersecurityEngine.simulate_attack_scenario(req)


# ---------------------------------------------------------------------------
# Auditoria y Cumplimiento
# ---------------------------------------------------------------------------

@router.get("/audit/checklist", summary="Checklist de auditoria ISO 27001 / RGPD para PYMEs")
async def audit_checklist():
    """Devuelve los 15 controles de auditoria de ciberseguridad para PYMEs."""
    return CourseCybersecurityEngine.get_audit_checklist()


@router.post("/audit/evaluate", summary="Evalua el nivel de madurez de ciberseguridad de la PYME")
async def audit_evaluate(req: AuditEvaluationRequest):
    """Calcula el porcentaje de cumplimiento y el nivel de madurez de seguridad de la organizacion."""
    return CourseCybersecurityEngine.evaluate_audit(req.respuestas)
