"""Módulo de Ciberseguridad Integrado para PYMEs (Basado en los 2 PDFs del Curso).

Implementa la lógica de:
1. Plan Director de Seguridad (PDS) y Políticas por Componente (ISO 27001, RGPD, NIST).
2. Matriz de Análisis y Gestión de Riesgos y BIA (RTO, RPO, MTTD, MTTR).
3. Planes de Continuidad de Negocio, DRP y Estrategias de Backup 3-2-1 / Borrado Seguro.
4. Simulador de Ataques y Defensas de las 18 Unidades Didácticas.
5. Auditoría de Ciberseguridad ISO 27001 / RGPD / Hardening de Puesto de Trabajo.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Modelos Pydantic
# ---------------------------------------------------------------------------

class PdsRequest(BaseModel):
    empresa_nombre: str = Field(..., example="TechSolutions PYME")
    sector: str = Field(..., example="Comercio Electronico / E-Commerce")
    num_empleados: int = Field(..., example=25)
    tiene_ecommerce: bool = Field(default=True)
    tiene_teletrabajo: bool = Field(default=True)
    usa_nube: bool = Field(default=True)
    usa_iot: bool = Field(default=False)


class RiskAssessmentRequest(BaseModel):
    activo_nombre: str = Field(..., example="Base de Datos de Clientes y Pedidos")
    probabilidad: int = Field(..., ge=1, le=5, description="1 (Muy baja) a 5 (Muy alta)")
    impacto: int = Field(..., ge=1, le=5, description="1 (Insignificante) a 5 (Catastrofico)")
    amenaza_tipo: str = Field(..., example="Ransomware / Exfiltracion de datos")
    estrategia_deseada: str = Field(default="mitigar", example="mitigar|transferir|evitar|aceptar")


class BiaRequest(BaseModel):
    servicio_critico: str = Field(..., example="Plataforma Web E-Commerce")
    impacto_financiero_hora: float = Field(..., example=1500.0)
    datos_sensibles: bool = Field(default=True)


class BackupCalculatorRequest(BaseModel):
    volumen_datos_gb: float = Field(..., example=500.0)
    metodo_backup: str = Field(default="incremental", example="full|incremental|diferencial|mirror|cdp")
    copias_fuera_sitio: int = Field(default=1)
    soportes_diferentes: int = Field(default=2)


class AttackSimulationRequest(BaseModel):
    vector_ataque: str = Field(
        ...,
        example="sqli_waf|ddos_syn_flood|phishing_spear|arp_poisoning|wpa3_byod|iot_botnet|biometric_spoof|ransomware_exfil|session_hijacking"
    )
    tecnologia_defensa: Optional[str] = Field(
        default=None,
        example="waf|mfa|edr|vpn|ids_ips|backup_321|radius|segmentacion"
    )


class AuditEvaluationRequest(BaseModel):
    respuestas: Dict[str, bool] = Field(..., description="Mapa de ID de control a True/False")


# ---------------------------------------------------------------------------
# Motor principal
# ---------------------------------------------------------------------------

class CourseCybersecurityEngine:
    """Motor principal que compila los conocimientos de las 18 Unidades Didacticas."""

    @staticmethod
    def generate_pds(req: PdsRequest) -> Dict[str, Any]:
        """Genera un Plan Director de Seguridad (PDS) completo adaptado a la PYME."""
        e_comm_str = "Si" if req.tiene_ecommerce else "No"
        tele_str = "con teletrabajo" if req.tiene_teletrabajo else "presenciales"
        alcance = (
            f"Proteccion integral de la infraestructura digital, portal e-commerce ({e_comm_str}), "
            f"puestos de trabajo {tele_str} ({req.num_empleados} usuarios) y servicios en nube."
        )

        politica_rrhh = [
            "Acuerdos de confidencialidad (NDA) obligatorios firmados en la contratacion.",
            "Programa continuo de concienciacion y simulacros periodicos de Phishing.",
            "Procedimiento formal de desvinculacion (offboarding) con revocacion inmediata de accesos.",
            "Politica de uso aceptable de recursos corporativos y codigo de conducta digital.",
        ]

        politica_tecnologica = [
            "Antivirus / Antimalware centralizado con analisis heuristico y firmas en tiempo real.",
            "Gestion estricta de parches (servidores, S.O. y aplicaciones en menos de 30 dias).",
            "Cifrado AES-256 para datos en reposo y TLS 1.3 para datos en transito.",
            "Control de accesos basado en roles (RBAC) y Autenticacion Multifactor (MFA) obligatoria.",
            "Segmentacion de red corporativa, red de invitados y Zona Desmilitarizada (DMZ).",
        ]
        if req.tiene_ecommerce:
            politica_tecnologica.append(
                "Despliegue de Web Application Firewall (WAF) contra SQLi, XSS y CSRF."
            )
        if req.usa_iot:
            politica_tecnologica.append(
                "Aislamiento de dispositivos IoT/IIoT en VLAN independiente sin acceso a red interna."
            )

        politica_organizativa = [
            "Asignacion clara de roles: CISO (Estrategia), Equipo TI (Operativa), Compliance Officer (Regulacion).",
            "Alineacion con norma ISO/IEC 27001 (SGSI) y catalogo de controles ISO/IEC 27002 / NIST SP 800-53.",
            "Cumplimiento normativo con RGPD, LOPDGDD y retencion fiscal 4 años (Ley General Tributaria).",
            "Revision anual del Plan Director de Seguridad y tras incidentes de seguridad significativos.",
        ]

        politica_fisica = [
            "Control de acceso fisico a CPD/servidores mediante biometria o tarjetas electronicas.",
            "Sistemas de alimentacion ininterrumpida (SAI/UPS) y proteccion contra desastres.",
            "Politica de escritorio limpio y auto-bloqueo de pantalla tras 5 minutos de inactividad.",
            "Restriccion y cifrado obligatorio de dispositivos extraibles (USB, discos portatiles).",
        ]

        fases_pdca = {
            "Plan (Planificar)": "Analisis de contexto, inventario de activos criticos y evaluacion de riesgos BIA.",
            "Do (Hacer)": "Implementacion de controles tecnicos, despliegue de politicas y capacitacion de personal.",
            "Check (Verificar)": "Auditorias de seguridad (internas/externas), metricas de incidentes y revision de logs SIEM.",
            "Act (Actuar)": "Aplicacion de acciones correctivas, actualizacion de umbrales y mejora continua del SGSI.",
        }

        return {
            "empresa": req.empresa_nombre,
            "sector": req.sector,
            "num_empleados": req.num_empleados,
            "alcance": alcance,
            "fases_ciclo_pdca": fases_pdca,
            "politicas_por_componente": {
                "recursos_humanos": politica_rrhh,
                "recursos_tecnologicos": politica_tecnologica,
                "recursos_organizativos": politica_organizativa,
                "recursos_fisicos": politica_fisica,
            },
            "marcos_normativos": [
                "ISO/IEC 27001:2022",
                "ISO/IEC 27002",
                "RGPD / LOPDGDD",
                "NIST SP 800-53",
                "Ley General Tributaria (Art. 66 — 4 años retention)",
            ],
            "resumen_ejecutivo": (
                f"Plan Director de Seguridad formalizado para {req.empresa_nombre}. "
                "Proporciona el marco estrategico para garantizar la confidencialidad, "
                "integridad y disponibilidad (Triada CIA) de los activos digitales."
            ),
        }

    @staticmethod
    def assess_risk(req: RiskAssessmentRequest) -> Dict[str, Any]:
        """Calcula el nivel de riesgo (R = P x I) y determina el tratamiento de riesgo."""
        valor_riesgo = req.probabilidad * req.impacto
        if valor_riesgo >= 16:
            nivel = "CRITICO"
            color = "rose"
            accion = "Respuesta inmediata exigida. Detener actividad insegura o desplegar mitigacion de emergencia."
        elif valor_riesgo >= 10:
            nivel = "ALTO"
            color = "orange"
            accion = "Planificar controles correctivos y tecnicos priorizados en menos de 14 dias."
        elif valor_riesgo >= 5:
            nivel = "MEDIO"
            color = "amber"
            accion = "Supervision periodica y aplicacion de controles preventivos en el proximo ciclo."
        else:
            nivel = "BAJO"
            color = "emerald"
            accion = "Aceptar riesgo bajo monitoreo rutinario de logs."

        estrategias_explicacion = {
            "mitigar": "Desplegar controles tecnicos/organizativos (Firewall, WAF, Cifrado, MFA) para reducir P o I.",
            "transferir": "Contratar un ciberseguro o externalizar la infraestructura a un proveedor cloud certificado.",
            "evitar": "Modificar el proceso de negocio o eliminar el componente que genera el riesgo elevado.",
            "aceptar": "Asumir el riesgo residual cuando el coste de la mitigacion supera el beneficio economico.",
        }

        return {
            "activo": req.activo_nombre,
            "amenaza": req.amenaza_tipo,
            "probabilidad": req.probabilidad,
            "impacto": req.impacto,
            "valor_riesgo_total": valor_riesgo,
            "nivel_riesgo": nivel,
            "color_badge": color,
            "accion_recomendada": accion,
            "estrategia_seleccionada": req.estrategia_deseada,
            "explicacion_estrategia": estrategias_explicacion.get(req.estrategia_deseada, "Mitigacion estandar"),
            "formula": "Riesgo = Probabilidad (1-5) x Impacto (1-5)",
        }

    @staticmethod
    def assess_bia(req: BiaRequest) -> Dict[str, Any]:
        """Realiza el Analisis de Impacto en el Negocio (BIA) definiendo RTO, RPO, MTTD y MTTR."""
        if req.datos_sensibles:
            rto_horas = 2.0
            rpo_minutos = 15.0
            mttd_minutos = 10.0
            mttr_horas = 1.5
        else:
            rto_horas = 8.0
            rpo_minutos = 120.0
            mttd_minutos = 30.0
            mttr_horas = 4.0

        coste_parada_24h = req.impacto_financiero_hora * 24.0

        return {
            "servicio_critico": req.servicio_critico,
            "contiene_datos_sensibles": req.datos_sensibles,
            "indicadores_continuidad": {
                "RTO_tiempo_maximo_tolerable_recuperacion": f"{rto_horas} horas",
                "RPO_perdida_maxima_tolerable_datos": f"{rpo_minutos} minutos",
                "MTTD_tiempo_promedio_deteccion": f"{mttd_minutos} minutos",
                "MTTR_tiempo_promedio_restauracion": f"{mttr_horas} horas",
            },
            "impacto_economico_estimado": {
                "coste_por_hora": f"{req.impacto_financiero_hora} EUR",
                "coste_parada_24h": f"{coste_parada_24h} EUR",
            },
            "recomendacion_bcp_drp": (
                "Se requiere replicacion en tiempo real en la nube y servidor de respaldo "
                "activo-pasivo para cumplir el RTO/RPO definido."
            ),
        }

    @staticmethod
    def calculate_backup_drp(req: BackupCalculatorRequest) -> Dict[str, Any]:
        """Evalua la estrategia de backup segun la regla 3-2-1 y esquema GFS."""
        cumple_321 = req.copias_fuera_sitio >= 1 and req.soportes_diferentes >= 2

        restauracion_info = {
            "full": "Restauracion completa directa desde el ultimo conjunto. Mas rapida de restaurar pero consume mas espacio.",
            "incremental": "Requiere el ultimo Full + TODAS las copias incrementales intermedias. Ahorra espacio pero restauracion mas lenta.",
            "diferencial": "Requiere el ultimo Full + la ULTIMA copia diferencial. Equilibrio entre espacio y velocidad.",
            "mirror": "Replica exacta en tiempo real sin versionado. Acceso inmediato pero puede replicar corrupcion.",
            "cdp": "Continuous Data Protection: guarda cada cambio al instante. Permite recuperacion Point-In-Time exacta.",
        }

        borrado_seguro_metodos = {
            "HDD (Disco Magnetico)": "Sobrescritura multiple (DoD 5220.22-M) o Desmagnetizacion (Degaussing).",
            "SSD (Estado Solido)": "Comandos del fabricante (ATA Secure Erase / NVMe Format Cryptographic Erase). NO usar Degaussing.",
            "Dispositivos Extraibles / USB": "Cifrado BitLocker/VeraCrypt en uso, y destruccion fisica (trituracion mecanica) al retirarlo.",
        }

        evaluacion_str = (
            "Estrategia 3-2-1 VALIDA y robusta."
            if cumple_321
            else "ADVERTENCIA: No cumple la regla 3-2-1 (se requiere al menos 1 copia fuera del sitio y 2 soportes distintos)."
        )

        return {
            "volumen_datos_gb": req.volumen_datos_gb,
            "metodo_seleccionado": req.metodo_backup,
            "explicacion_metodo": restauracion_info.get(req.metodo_backup, "Respaldo estandar"),
            "regla_321": {
                "cumple": cumple_321,
                "copias_totales": 3 if cumple_321 else 2,
                "soportes_diferentes": req.soportes_diferentes,
                "copias_fuera_sitio": req.copias_fuera_sitio,
                "evaluacion": evaluacion_str,
            },
            "esquema_rotacion_gfs": {
                "Grandfather (Abuelos)": "1 backup completo mensual guardado durante 12 meses.",
                "Father (Padres)": "1 backup completo semanal guardado durante 4 semanas.",
                "Son (Hijos)": "Backups diarios (incrementales/diferenciales) guardados durante 7 dias.",
            },
            "protocolos_borrado_seguro": borrado_seguro_metodos,
        }

    @staticmethod
    def simulate_attack_scenario(req: AttackSimulationRequest) -> Dict[str, Any]:
        """Simula uno de los 9 escenarios de ataque/defensa del temario completo."""
        scenarios: Dict[str, Any] = {
            "arp_poisoning": {
                "nombre": "Ataque de Envenenamiento ARP (ARP Poisoning / Gateway Spoofing)",
                "unidad": "Unidad 9 Modulo 1 (Ataques a nivel de red) / Unidad 3 Modulo 1",
                "descripcion": "Un atacante en la LAN envia paquetes ARP falsificados para asociar su MAC a la IP del Router/Gateway corporativo.",
                "triada_afectada": "Confidencialidad e Integridad (Permite ataques Man-in-the-Middle - MitM).",
                "capa_defensa": "Capa de Red (Layer 2 / Switch)",
                "defensa_ideal": "Dynamic ARP Inspection (DAI), 802.1X, asignacion estatica de tabla ARP y cifrado TLS en aplicaciones.",
                "defensas_efectivas": ["ids_ips", "segmentacion", "radius", "vpn"],
            },
            "ddos_syn_flood": {
                "nombre": "Ataque DDoS SYN Flood a Servidor Web E-Commerce",
                "unidad": "Unidad 9 Modulo 1 (Denegacion de Servicio) / Unidad 7 Modulo 2",
                "descripcion": "Inundacion masiva de solicitudes TCP SYN sin completar el saludo de 3 vias, agotando la tabla de conexiones del servidor.",
                "triada_afectada": "Disponibilidad (Interrupcion total de la tienda online).",
                "capa_defensa": "Capa Perimetral / Nube (WAF / Anycast Anti-DDoS)",
                "defensa_ideal": "SYN Cookies, Limitacion de tasa (Rate Limiting), WAF en la nube y filtrado por proveedor ISP.",
                "defensas_efectivas": ["waf", "ids_ips"],
            },
            "phishing_spear": {
                "nombre": "Spear Phishing dirigido a Finanzas con archivo PDF Malicioso",
                "unidad": "Unidad 2 Modulo 1 (Ingenieria Social) / Unidad 2 Modulo 2",
                "descripcion": "Correo electronico hiperpersonalizado simulando un proveedor para ejecutar una carga util e infectar la estacion de trabajo.",
                "triada_afectada": "Confidencialidad, Integridad y Disponibilidad.",
                "capa_defensa": "Capa Humana + Capa de Aplicacion/Endpoint",
                "defensa_ideal": "Concienciacion continua, filtro Anti-Spam SPF/DKIM/DMARC, Autenticacion MFA y EDR en el endpoint.",
                "defensas_efectivas": ["mfa", "edr"],
            },
            "sqli_waf": {
                "nombre": "Inyeccion SQL (SQLi) en el formulario de Login del E-Commerce",
                "unidad": "Unidad 7 Modulo 2 (Seguridad Web) / Unidad 9 Modulo 1",
                "descripcion": "El atacante introduce OR 1=1 para eludir la validacion y extraer la base de datos de usuarios.",
                "triada_afectada": "Confidencialidad e Integridad de la base de datos.",
                "capa_defensa": "Capa de Aplicacion (WAF y Codigo seguro)",
                "defensa_ideal": "Consultas preparadas (Prepared Statements / ORM), validacion de entradas y Web Application Firewall (WAF).",
                "defensas_efectivas": ["waf", "edr"],
            },
            "wpa3_byod": {
                "nombre": "Dispositivo Personal Infectado (BYOD) en Red Wi-Fi Corporativa",
                "unidad": "Unidad 8 Modulo 2 / Unidad 5 Modulo 1 (Redes Inalambricas y BYOD)",
                "descripcion": "Un smartphone personal sin actualizar se conecta a la Wi-Fi corporativa e intenta movimiento lateral.",
                "triada_afectada": "Confidencialidad e Integridad de la red interna.",
                "capa_defensa": "Capa de Red Inalambrica y Dispositivos Moviles",
                "defensa_ideal": "WPA3-Enterprise con servidor RADIUS, solucion MDM (Mobile Device Management) y aislamiento en VLAN de invitados.",
                "defensas_efectivas": ["radius", "segmentacion", "vpn"],
            },
            "iot_botnet": {
                "nombre": "Compromiso de Camaras IP IoT para reclutamiento en Botnet DDoS",
                "unidad": "Unidad 9 Modulo 2 (Tecnologia IoT) / Unidad 2 Modulo 1 (Botnets)",
                "descripcion": "Atacante explota credenciales por defecto (admin/admin) y firmware desactualizado en sensores/camaras IoT.",
                "triada_afectada": "Disponibilidad e Integridad.",
                "capa_defensa": "Capa de Red y Dispositivos IoT",
                "defensa_ideal": "Cambio de contrasenas por defecto, actualizacion de firmware, Edge Computing seguro y segmentacion VLAN aislada.",
                "defensas_efectivas": ["segmentacion", "ids_ips"],
            },
            "biometric_spoof": {
                "nombre": "Ataque de Suplantacion Biometrica (Facial Presentation Attack)",
                "unidad": "Unidad 7 Modulo 1 (Sistemas Biometricos)",
                "descripcion": "Presentacion de una fotografia/video de alta resolucion frente a la camara de control de acceso fisico.",
                "triada_afectada": "Autenticidad y Confidencialidad.",
                "capa_defensa": "Capa Fisica / Biometrica",
                "defensa_ideal": "Deteccion de vida (Liveness Detection / Sensores termicos IR), autenticacion multifactor (Biometria + PIN) y calibracion EER.",
                "defensas_efectivas": ["mfa", "radius"],
            },
            "ransomware_exfil": {
                "nombre": "Ataque de Doble Extorsion por Ransomware",
                "unidad": "Unidad 3 Modulo 1 (Malware) / Unidad 6 Modulo 1 (Fuga de Datos / DLP)",
                "descripcion": "El malware exfiltra datos confidenciales antes de cifrar el sistema de archivos y pedir rescate en criptomonedas.",
                "triada_afectada": "Confidencialidad, Integridad y Disponibilidad.",
                "capa_defensa": "Capa de Datos + Aplicacion + Copias de Seguridad",
                "defensa_ideal": "Herramientas DLP (Data Loss Prevention), EDR con analisis del comportamiento, y Backups offline 3-2-1.",
                "defensas_efectivas": ["backup_321", "edr"],
            },
            "session_hijacking": {
                "nombre": "Secuestro de Sesion por Interceptacion de Token JWT/Cookie",
                "unidad": "Unidad 2 Modulo 1 (Autenticacion) / Unidad 7 Modulo 2",
                "descripcion": "El atacante captura la cookie de sesion sin atributos Secure y HttpOnly a traves de Wi-Fi abierta.",
                "triada_afectada": "Autenticidad y Confidencialidad.",
                "capa_defensa": "Capa de Aplicacion y Red",
                "defensa_ideal": "Cookies con atributos SameSite=Strict, Secure, HttpOnly, expiracion corta de tokens y uso obligatorio de VPN/TLS.",
                "defensas_efectivas": ["vpn", "waf"],
            },
        }

        data = scenarios.get(req.vector_ataque, scenarios["sqli_waf"])
        bloqueado = req.tecnologia_defensa in data["defensas_efectivas"]
        def_upper = req.tecnologia_defensa.upper() if req.tecnologia_defensa else "NINGUNA"

        if bloqueado:
            mensaje = (
                f"ATAQUE BLOQUEADO CON EXITO mediante {def_upper}. "
                "La capa de defensa contuvo el vector antes de comprometer el activo."
            )
        else:
            d_str = req.tecnologia_defensa or "Ninguna"
            mensaje = (
                f"ATAQUE EXITOSO / ALERTA GENERADA. La defensa seleccionada ('{d_str}') no fue suficiente. "
                f"Se recomienda implementar: {data['defensa_ideal']}."
            )

        return {
            "vector": req.vector_ataque,
            "nombre_escenario": data["nombre"],
            "unidad_didactica": data["unidad"],
            "descripcion": data["descripcion"],
            "triada_cia_afectada": data["triada_afectada"],
            "capa_defensa_afectada": data["capa_defensa"],
            "defensa_recomendada": data["defensa_ideal"],
            "defensas_efectivas": data["defensas_efectivas"],
            "defensa_usuario": req.tecnologia_defensa,
            "resultado_simulacion": {
                "bloqueado": bloqueado,
                "mensaje": mensaje,
            },
        }

    @staticmethod
    def get_audit_checklist() -> Dict[str, Any]:
        """Devuelve el catalogo de 15 controles clave de auditoria ISO 27001/RGPD para PYMEs."""
        controles = [
            {"id": "c1",  "categoria": "Politicas y PDS",          "titulo": "Existe un Plan Director de Seguridad (PDS) formalizado y revisado al menos 1 vez al año."},
            {"id": "c2",  "categoria": "Politicas y PDS",          "titulo": "Se han formalizado politicas de seguridad para RRHH, Tecnologia, Organizacion y Seguridad Fisica."},
            {"id": "c3",  "categoria": "Control de Acceso",        "titulo": "Se aplica el principio de minimo privilegio y control de acceso basado en roles (RBAC)."},
            {"id": "c4",  "categoria": "Control de Acceso",        "titulo": "La Autenticacion Multifactor (MFA) es obligatoria en accesos remotos, VPN y cuentas administrativas."},
            {"id": "c5",  "categoria": "Puesto de Trabajo",        "titulo": "Los equipos tienen antivirus/antimalware actualizado, firewall activo y auto-bloqueo tras inactividad."},
            {"id": "c6",  "categoria": "Puesto de Trabajo",        "titulo": "Los discos duros de portatiles y memorias USB estan cifrados con AES-256 / BitLocker."},
            {"id": "c7",  "categoria": "Redes y WiFi",             "titulo": "La red Wi-Fi utiliza WPA2/WPA3-Enterprise y la red de invitados esta aislada en una VLAN independiente."},
            {"id": "c8",  "categoria": "Redes y WiFi",             "titulo": "El router corporativo tiene cambiadas las credenciales por defecto y el servicio WPS desactivado."},
            {"id": "c9",  "categoria": "Seguridad Web",            "titulo": "Las aplicaciones web y tienda online estan protegidas por WAF contra SQLi, XSS y CSRF."},
            {"id": "c10", "categoria": "Backup y DRP",             "titulo": "Se cumple la regla de copias de seguridad 3-2-1 con al menos 1 copia almacenada fuera del sitio o en nube."},
            {"id": "c11", "categoria": "Backup y DRP",             "titulo": "Se realizan pruebas periodicas de restauracion de datos y se han definido metricas RTO y RPO."},
            {"id": "c12", "categoria": "Gestion de Datos",         "titulo": "Los datos empresariales estan clasificados (Publica, Interna, Confidencial, Estrictamente confidencial)."},
            {"id": "c13", "categoria": "Gestion de Datos",         "titulo": "Existen procedimientos de borrado seguro (Overwriting, Degaussing, Secure Erase) para soportes retirados."},
            {"id": "c14", "categoria": "Cumplimiento y RGPD",      "titulo": "Se cumple con el RGPD y se conserva la documentacion fiscal durante 4 años (Ley General Tributaria)."},
            {"id": "c15", "categoria": "Formacion y Concienciacion","titulo": "El personal recibe formacion regular en ciberseguridad y prevencion de Phishing e Ingenieria Social."},
        ]
        return {"total_controles": len(controles), "controles": controles}

    @staticmethod
    def evaluate_audit(respuestas: Dict[str, bool]) -> Dict[str, Any]:
        """Evalua el nivel de madurez de ciberseguridad de la PYME segun las respuestas del checklist."""
        checklist = CourseCybersecurityEngine.get_audit_checklist()["controles"]
        total = len(checklist)
        cumplidos = sum(1 for c in checklist if respuestas.get(c["id"], False))
        porcentaje = round((cumplidos / total) * 100, 1)

        if porcentaje >= 85:
            madurez = "NIVEL AVANZADO / OPTIMIZADO (Cumplimiento ISO 27001 robusto)"
            color = "emerald"
        elif porcentaje >= 60:
            madurez = "NIVEL INTERMEDIO (Medidas aceptables, requiere reforzar parches/DRP)"
            color = "amber"
        else:
            madurez = "NIVEL INICIAL / VULNERABLE (Riesgo alto de brecha o sancion RGPD)"
            color = "rose"

        hallazgos_faltantes = [c["titulo"] for c in checklist if not respuestas.get(c["id"], False)]

        return {
            "total_controles": total,
            "cumplidos": cumplidos,
            "porcentaje_cumplimiento": porcentaje,
            "nivel_madurez": madurez,
            "color_badge": color,
            "puntos_mejora_prioritarios": hallazgos_faltantes[:5],
            "resumen": f"La organizacion cumple el {porcentaje}% de los controles clave de ciberseguridad para PYMEs.",
        }
