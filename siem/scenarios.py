"""Biblioteca de escenarios para el simulador de crisis.

Cada escenario es una secuencia de pasos con delays reales entre ellos. Cada
paso, al dispararse, se convierte en un `Event` normal que pasa por el mismo
camino que un evento real (`correlate_event` + `store.add_event`, el mismo
que usa `POST /v1/monitoring/ingest`) -- ver `siem/simulator.py`. No hay un
motor "de mentira" aparte: los incidentes que genera practicar aquí son
indistinguibles de los que generaría un ataque de verdad, y quedan
persistidos en el mismo siem.db, no en un sandbox descartable.
"""
from typing import Optional

from pydantic import BaseModel, Field

from siem.models import Severity


class ScenarioStep(BaseModel):
    delay_seconds: float = 0  # espera ANTES de inyectar este evento
    asset_name: str
    event_type: str
    severity: Severity
    summary: str
    description: str = ""
    source: str = "simulador"


class Scenario(BaseModel):
    id: str
    name: str
    description: str
    steps: list[ScenarioStep] = Field(default_factory=list)


SCENARIOS: dict[str, Scenario] = {
    "ransomware": Scenario(
        id="ransomware",
        name="Ataque de ransomware",
        description=(
            "Compromiso inicial, escalada de privilegios, movimiento lateral "
            "y cifrado masivo en servidores de producción."
        ),
        steps=[
            ScenarioStep(
                delay_seconds=0, asset_name="web-prod-01", event_type="acceso_sospechoso",
                severity=Severity.MEDIUM, summary="Inicio de sesión desde IP no habitual",
                description="Login exitoso fuera del rango horario habitual desde 185.220.101.7 (nodo de salida Tor).",
            ),
            ScenarioStep(
                delay_seconds=4, asset_name="web-prod-01", event_type="escalada_privilegios",
                severity=Severity.HIGH, summary="Escalada de privilegios detectada",
                description="El usuario comprometido obtuvo permisos de administrador local.",
            ),
            ScenarioStep(
                delay_seconds=4, asset_name="db-prod-01", event_type="movimiento_lateral",
                severity=Severity.HIGH, summary="Movimiento lateral hacia base de datos",
                description="Conexión RDP no habitual desde web-prod-01 hacia db-prod-01.",
            ),
            ScenarioStep(
                delay_seconds=5, asset_name="db-prod-01", event_type="cifrado_masivo",
                severity=Severity.CRITICAL, summary="Cifrado masivo de archivos detectado",
                description="Más de 4.000 archivos renombrados con extensión .locked en menos de 2 minutos.",
            ),
            ScenarioStep(
                delay_seconds=3, asset_name="backup-01", event_type="acceso_no_autorizado",
                severity=Severity.CRITICAL, summary="Intento de borrado de copias de seguridad",
                description="Se detectó un intento de eliminar snapshots de backup, bloqueado por política de retención.",
            ),
        ],
    ),
    "phishing_ddos": Scenario(
        id="phishing_ddos",
        name="Phishing + DDoS simultáneo",
        description=(
            "Campaña de phishing dirigida a Finanzas mientras un ataque DDoS "
            "satura el sitio público: presión simultánea en dos frentes."
        ),
        steps=[
            ScenarioStep(
                delay_seconds=0, asset_name="correo-corporativo", event_type="phishing",
                severity=Severity.MEDIUM, summary="Campaña de phishing detectada",
                description="17 empleados recibieron un correo suplantando a Dirección Financiera pidiendo una transferencia urgente.",
            ),
            ScenarioStep(
                delay_seconds=2, asset_name="web-prod-01", event_type="trafico_anomalo",
                severity=Severity.HIGH, summary="Volumen de tráfico anómalo",
                description="Tráfico entrante x40 sobre la media desde más de 2.000 IPs distintas.",
            ),
            ScenarioStep(
                delay_seconds=3, asset_name="finanzas-pc-04", event_type="phishing",
                severity=Severity.HIGH, summary="Clic en enlace de phishing confirmado",
                description="Un usuario de Finanzas hizo clic en el enlace y envió sus credenciales.",
            ),
            ScenarioStep(
                delay_seconds=3, asset_name="web-prod-01", event_type="denegacion_servicio",
                severity=Severity.CRITICAL, summary="Servicio web caído por saturación",
                description="El balanceador dejó de responder: servicio público no disponible.",
            ),
        ],
    ),
    "fuga_datos": Scenario(
        id="fuga_datos",
        name="Fuga de datos",
        description="Exfiltración progresiva de datos de clientes hacia un destino externo no autorizado.",
        steps=[
            ScenarioStep(
                delay_seconds=0, asset_name="db-prod-01", event_type="consulta_anomala",
                severity=Severity.LOW, summary="Consulta masiva a tabla de clientes",
                description="Una cuenta de servicio ejecutó un SELECT * sobre la tabla clientes fuera de su patrón habitual.",
            ),
            ScenarioStep(
                delay_seconds=3, asset_name="db-prod-01", event_type="exfiltracion",
                severity=Severity.HIGH, summary="Transferencia saliente inusual",
                description="2.3 GB transferidos hacia una IP externa no catalogada en los últimos 10 minutos.",
            ),
            ScenarioStep(
                delay_seconds=4, asset_name="db-prod-01", event_type="exfiltracion",
                severity=Severity.CRITICAL, summary="Confirmada exfiltración de datos de clientes",
                description="El DLP confirmó coincidencia de patrones de PII (DNI, email, tarjeta) en el tráfico saliente.",
            ),
        ],
    ),
    # -------------------------------------------------------------------
    # Añadidos 2026-07-05 junto al catálogo de 30 amenazas
    # (siem/threats_catalog.py) y su detección por palabra clave
    # (siem/threat_detection.py). Los tres escenarios originales de arriba
    # ya cubrían ransomware(6), phishing(3), DDoS(1) e inyección SQL(8) de
    # forma indirecta; estos seis cubren el resto de las 10 amenazas nuevas
    # investigadas para esa ronda (21-30), eligiendo a propósito el
    # vocabulario exacto de las keywords del catálogo en `summary`/
    # `description` para que la detección dispare de verdad al correr el
    # escenario -- no son solo texto narrativo, son la prueba viva de que
    # detect_threats() funciona sobre tráfico "real" (ver
    # tests/test_threat_detection.py para la misma detección de forma
    # aislada, sin depender de los delays de estos escenarios).
    # -------------------------------------------------------------------
    "cadena_suministro": Scenario(
        id="cadena_suministro",
        name="Ataque a la cadena de suministro",
        description="Una dependencia de código abierto usada en el pipeline de CI/CD resulta comprometida por su propio proveedor.",
        steps=[
            ScenarioStep(
                delay_seconds=0, asset_name="ci-cd-pipeline", event_type="dependencia_comprometida",
                severity=Severity.MEDIUM, summary="Dependencia comprometida detectada en el pipeline",
                description="Un paquete de código abierto usado en el CI/CD fue identificado como parte de un ataque a la cadena de suministro.",
            ),
            ScenarioStep(
                delay_seconds=4, asset_name="build-server-01", event_type="ci_cd_comprometido",
                severity=Severity.HIGH, summary="Proveedor comprometido confirmado",
                description="El proveedor del paquete afectado confirmó que su repositorio fue comprometido, afectando a múltiples clientes.",
            ),
        ],
    ),
    "ingenieria_social_ia": Scenario(
        id="ingenieria_social_ia",
        name="Ingeniería social con IA + fraude por correo",
        description="Un deepfake de voz autoriza un pago fraudulento, seguido de un compromiso de correo corporativo para consumarlo.",
        steps=[
            ScenarioStep(
                delay_seconds=0, asset_name="finanzas-pc-02", event_type="deepfake_detectado",
                severity=Severity.HIGH, summary="Deepfake de voz usado para autorizar un pago",
                description="Se recibió una llamada con voz clonada simulando al director financiero pidiendo un cambio de cuenta bancaria urgente.",
            ),
            ScenarioStep(
                delay_seconds=3, asset_name="finanzas-pc-02", event_type="fraude_confirmado",
                severity=Severity.CRITICAL, summary="Transferencia fraudulenta confirmada",
                description="Se confirmó un compromiso de correo corporativo: el dominio usado era casi idéntico al real.",
            ),
        ],
    ),
    "cryptojacking_cloud": Scenario(
        id="cryptojacking_cloud",
        name="Configuración errónea en la nube + cryptojacking",
        description="Un bucket cloud mal configurado permite acceso no autorizado, usado después para minar criptomonedas a costa de la organización.",
        steps=[
            ScenarioStep(
                delay_seconds=0, asset_name="cloud-storage-01", event_type="configuracion_erronea",
                severity=Severity.MEDIUM, summary="Bucket expuesto públicamente en el proveedor cloud",
                description="Se detectó un bucket expuesto por permisos IAM demasiado amplios, accesible sin autenticación.",
            ),
            ScenarioStep(
                delay_seconds=4, asset_name="cloud-compute-02", event_type="consumo_anomalo_cpu",
                severity=Severity.HIGH, summary="Consumo anómalo de CPU en instancias cloud",
                description="Minado de criptomonedas no autorizado tras el acceso indebido al bucket expuesto.",
            ),
        ],
    ),
    "relleno_credenciales": Scenario(
        id="relleno_credenciales",
        name="Relleno de credenciales (Credential Stuffing)",
        description="Credenciales filtradas en otra brecha se usan de forma automatizada y masiva contra el portal de clientes.",
        steps=[
            ScenarioStep(
                delay_seconds=0, asset_name="portal-clientes", event_type="login_automatizado_masivo",
                severity=Severity.MEDIUM, summary="Login automatizado masivo detectado",
                description="Miles de intentos de acceso con credenciales filtradas de otra brecha en cuestión de minutos.",
            ),
            ScenarioStep(
                delay_seconds=3, asset_name="portal-clientes", event_type="acceso_no_autorizado",
                severity=Severity.HIGH, summary="Acceso exitoso mediante relleno de credenciales",
                description="Una cuenta de cliente fue comprometida: la contraseña coincidía con una filtración de otro servicio.",
            ),
        ],
    ),
    "botnet_iot_ddos": Scenario(
        id="botnet_iot_ddos",
        name="Botnet de IoT + DDoS",
        description="Dispositivos IoT con credenciales por defecto son reclutados en una botnet y usados para un DDoS masivo.",
        steps=[
            ScenarioStep(
                delay_seconds=0, asset_name="camara-ip-recepcion", event_type="dispositivo_iot_comprometido",
                severity=Severity.MEDIUM, summary="Cámara comprometida detectada en la red",
                description="Una cámara IP con credenciales por defecto fue reclutada en una botnet IoT.",
            ),
            ScenarioStep(
                delay_seconds=4, asset_name="web-prod-01", event_type="denegacion_servicio",
                severity=Severity.CRITICAL, summary="Ataque DDoS masivo desde dispositivos IoT comprometidos",
                description="Tráfico entrante x60 sobre la media proveniente de miles de dispositivos IoT comprometidos en todo el mundo.",
            ),
        ],
    ),
    "api_ia_sim": Scenario(
        id="api_ia_sim",
        name="Ataque a API + IA comprometida + secuestro de SIM",
        description="Un endpoint de API mal protegido, un asistente de IA manipulado y un secuestro de SIM contra un directivo, en la misma tarde.",
        steps=[
            ScenarioStep(
                delay_seconds=0, asset_name="api-publica-01", event_type="endpoint_expuesto",
                severity=Severity.MEDIUM, summary="Ataque a API detectado en endpoint expuesto",
                description="Un endpoint expuesto sin autorización a nivel de objeto permitió acceder a datos de otros usuarios.",
            ),
            ScenarioStep(
                delay_seconds=3, asset_name="asistente-ia-soporte", event_type="prompt_injection",
                severity=Severity.HIGH, summary="Inyección de prompt detectada en el asistente de IA",
                description="Un usuario externo logró una inyección de prompt que hizo al agente autónomo comprometido revelar datos internos.",
            ),
            ScenarioStep(
                delay_seconds=3, asset_name="movil-corporativo-ceo", event_type="secuestro_sim",
                severity=Severity.CRITICAL, summary="Secuestro de SIM confirmado en dispositivo corporativo",
                description="Se confirmó un secuestro de SIM: el operador reportó una portabilidad fraudulenta del número corporativo.",
            ),
        ],
    ),
}


def get_scenario(scenario_id: str) -> Optional[Scenario]:
    return SCENARIOS.get(scenario_id)


def list_scenarios() -> list[Scenario]:
    return list(SCENARIOS.values())
