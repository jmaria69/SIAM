"""Catálogo de amenazas de ciberseguridad (30 entradas).

Las 20 primeras (ids 1-20) las proporcionó José a partir de material propio;
las 10 siguientes (ids 21-30) se investigaron en julio de 2026 para cubrir
las categorías que ese listado clásico no recogía (cadena de suministro, IA
como vector y como objetivo, nube, APIs, credential stuffing, cryptojacking,
BEC, SIM swapping, botnets IoT) -- ver fuentes citadas junto a cada entrada
nueva en CLAUDE.md.

Cada entrada tiene un campo `keywords`: subcadenas en minúsculas que
`siem/threat_detection.py` busca dentro de `event_type + summary +
description` para asignar `threat_ids` a un evento/incidente. Es
detección determinista por palabra clave (decisión explícita de José,
2026-07-05), no clasificación por IA -- funciona siempre, sin depender de
AI_PROVIDER ni de coste de inferencia, igual que el resto de la
correlación en `siem/correlation.py`.

Las keywords se eligieron para casar con el vocabulario que ya usan los
escenarios del simulador (`siem/scenarios.py`) y con lenguaje natural
razonable en `summary`/`description` de eventos reales -- no son exhaustivas
ni pretenden serlo; es un MVP de reglas, ampliable sin tocar la lógica de
`threat_detection.py`, solo añadiendo palabras a la lista.
"""
from typing import Optional, TypedDict


class ThreatEntry(TypedDict):
    id: int
    nombre: str
    definicion: str
    riesgo: str
    prevencion: str
    keywords: list[str]
    # Campos MITRE ATT&CK — NO se escriben a mano en cada entrada del literal
    # de abajo; se inyectan al cargar el módulo desde la tabla `MITRE_MAP`
    # (ver más abajo). Se mantienen aquí en el TypedDict para que el tipo de
    # una entrada ya enriquecida sea correcto y para documentar que existen.
    mitre_tactic: str       # nombre legible de la táctica, p.ej. "Acceso inicial"
    mitre_tactic_id: str    # id ATT&CK de la táctica, p.ej. "TA0001"
    mitre_technique: str    # nombre de la técnica, p.ej. "Phishing"
    mitre_technique_id: str # id de la técnica, p.ej. "T1566"


THREATS_CATALOG: list[ThreatEntry] = [
    {
        "id": 1,
        "nombre": "Ataques DoS y DDoS",
        "definicion": "Inundar un sistema con solicitudes falsas para agotar sus recursos y apagarlo. DoS usa una sola fuente; DDoS utiliza una red masiva de computadoras infectadas (bots).",
        "riesgo": "Interrumpir el servicio (no buscan acceder a datos, a menos que se use como distracción para otro ataque).",
        "prevencion": "Instalar cortafuegos que filtren tráfico falso y diseñar arquitecturas de red resilientes (ej. SD-WAN).",
        # Nota (falso positivo real): el acrónimo suelto "dos " casaba dentro
        # de palabras españolas comunes ("fallidos ", "todos ", "saludos "...)
        # -> un evento de fuerza bruta ("intentos de login fallidos") disparaba
        # DoS por error. Se sustituye por formas específicas del acrónimo
        # ("ataque dos", "dos/ddos", "(dos)"); "ddos" y "denegacion_servicio"
        # (que usa el simulador) siguen cubriendo los casos reales.
        "keywords": ["ddos", "ataque dos", "dos/ddos", "(dos)", "denegacion_servicio", "denegación de servicio", "saturacion", "saturación", "trafico_anomalo", "tráfico anómalo", "volumen de tráfico"],
    },
    {
        "id": 2,
        "nombre": "Ataques MITM (Hombre en el Medio)",
        "definicion": "Interceptación y espionaje de datos en tránsito entre dos partes que creen comunicarse de forma segura. El atacante se sitúa en el medio para leer o modificar la información antes de que llegue a su destino.",
        "riesgo": "Robo o alteración de datos en tránsito sin que ninguna de las partes lo note.",
        "prevencion": "Implementar cifrado sólido en puntos de acceso y utilizar redes privadas virtuales (VPN).",
        "keywords": ["mitm", "hombre en el medio", "man-in-the-middle", "intercept"],
    },
    {
        "id": 3,
        "nombre": "Ataques de Phishing (Suplantación de identidad)",
        "definicion": "Engañar al usuario para obtener datos confidenciales o infectar el equipo con malware, mediante correos con enlaces o archivos maliciosos usando la identidad de fuentes confiables.",
        "riesgo": "Robo de credenciales/datos confidenciales o infección del equipo.",
        "prevencion": "No abrir enlaces sospechosos y verificar exhaustivamente que los encabezados del correo coincidan con el dominio real.",
        "keywords": ["phishing", "correo suplantando", "enlace de phishing", "clic en enlace"],
    },
    {
        "id": 4,
        "nombre": "Ataques de Whale-Phishing (Whaling)",
        "definicion": "Estafar a los \"peces gordos\" de una empresa (altos ejecutivos y directores).",
        "riesgo": "Acceso a secretos comerciales de alto valor o forzar el pago de rescates para evitar daños reputacionales.",
        "prevencion": "Aplicar las mismas medidas del phishing, extremando la revisión de remitentes y archivos adjuntos.",
        "keywords": ["whaling", "whale-phishing", "whale phishing", "ceo fraud", "suplantando a dirección", "suplantando al ceo"],
    },
    {
        "id": 5,
        "nombre": "Ataques de Phishing Dirigido (Spear Phishing)",
        "definicion": "Atacar a un individuo específico mediante mensajes personalizados basados en una investigación previa, suplantando la identidad de un conocido y clonando páginas web reales.",
        "riesgo": "Ganarse la confianza de la víctima para robar datos o credenciales.",
        "prevencion": "Inspeccionar minuciosamente los campos del correo y nunca introducir datos en enlaces cuya legitimidad no esté verificada.",
        "keywords": ["spear phishing", "spear-phishing", "phishing dirigido", "clonacion", "clonación de página"],
    },
    {
        "id": 6,
        "nombre": "Ransomware",
        "definicion": "Secuestrar el sistema o los datos de la víctima mediante cifrado y exigir el pago de un rescate para recuperarlos. Se introduce vía web/adjuntos, se propaga por redes internas o USB, y puede permanecer inactivo antes de cifrar simultáneamente múltiples sistemas.",
        "riesgo": "Una de las amenazas más críticas a nivel mundial, especialmente en infraestructuras críticas, salud y cadenas de suministro.",
        "prevencion": "Vigilancia sobre enlaces y sitios visitados; firewalls de próxima generación (NGFW) con inspección profunda de paquetes basada en IA.",
        "keywords": ["ransomware", "cifrado_masivo", "cifrado masivo", "archivos cifrados", "extensión .locked", ".locked", "rescate"],
    },
    {
        "id": 7,
        "nombre": "Ataques de contraseña",
        "definicion": "Obtener credenciales de acceso mediante localización física de contraseñas anotadas, interceptación de transmisiones no cifradas, ingeniería social, fuerza bruta con datos personales o ataque de diccionario.",
        "riesgo": "Infiltración en sistemas o redes mediante credenciales robadas o adivinadas.",
        "prevencion": "Implementar bloqueo automático tras intentos fallidos y cambiar credenciales si se detectan intentos no autorizados.",
        "keywords": ["ataque de contraseña", "ataque de diccionario", "password attack", "contraseña adivinada", "contraseña anotada"],
    },
    {
        "id": 8,
        "nombre": "Ataques de inyección de SQL",
        "definicion": "Penetrar bases de datos de sitios web insertando comandos de consulta maliciosos en campos de entrada que el servidor ejecuta, permitiendo tomar control de la base de datos.",
        "riesgo": "Divulgación, modificación o eliminación de datos sensibles.",
        "prevencion": "Aplicar el modelo de mínimo privilegio, restringiendo el acceso a bases de datos clave a quien lo necesite para su función.",
        "keywords": ["inyeccion sql", "inyección sql", "sql injection", "sqli", "consulta_anomala", "select * "],
    },
    {
        "id": 9,
        "nombre": "Interpretación de URL (Intoxicación por URL)",
        "definicion": "Acceder a áreas restringidas alterando la sintaxis de las direcciones web para identificar vulnerabilidades de navegación y forzar el acceso a páginas de administración o back-end sin controles adecuados.",
        "riesgo": "Acceso no autorizado a páginas de administración o back-end.",
        "prevencion": "Configurar correctamente los permisos del servidor y exigir autenticación robusta en todas las páginas sensibles.",
        "keywords": ["interpretacion de url", "interpretación de url", "intoxicacion por url", "url tampering", "manipulacion de url", "manipulación de parámetros"],
    },
    {
        "id": 10,
        "nombre": "Suplantación de identidad del DNS",
        "definicion": "Alteración de los registros del sistema de nombres de dominio para desviar a los usuarios hacia servidores fraudulentos.",
        "riesgo": "Exposición de datos privados y suplantación de la identidad corporativa ante los visitantes.",
        "prevencion": "Mantener el software de los servidores DNS actualizado para mitigar vulnerabilidades conocidas.",
        "keywords": ["dns spoofing", "suplantacion de dns", "suplantación de dns", "envenenamiento dns", "registros dns alterados"],
    },
    {
        "id": 11,
        "nombre": "Secuestro de sesiones",
        "definicion": "Interceptación y toma de control de una sesión de comunicación activa entre un usuario y un servidor.",
        "riesgo": "El atacante puede realizar acciones en nombre del usuario legítimo una vez establecida la conexión de confianza.",
        "prevencion": "Implementación de túneles cifrados (VPN) para proteger las comunicaciones con sistemas críticos.",
        "keywords": ["secuestro de sesion", "secuestro de sesión", "session hijacking", "token de sesion robado"],
    },
    {
        "id": 12,
        "nombre": "Ataques de fuerza bruta",
        "definicion": "Intentos masivos y automatizados para adivinar credenciales mediante herramientas de procesamiento rápido.",
        "riesgo": "Acceso no autorizado a cuentas con contraseñas débiles o predecibles.",
        "prevencion": "Aplicar bloqueo de cuenta tras intentos fallidos y promover contraseñas de alta complejidad y aleatoriedad.",
        "keywords": ["fuerza bruta", "brute force", "intentos de acceso fallidos", "multiples intentos de login"],
    },
    {
        "id": 13,
        "nombre": "Ataques web",
        "definicion": "Explotación de debilidades en la lógica de las aplicaciones web, incluyendo técnicas como CSRF o manipulación de parámetros de seguridad.",
        "riesgo": "Ejecución de comandos no autorizados o evasión de controles de acceso integrados en la aplicación.",
        "prevencion": "Auditorías de código frecuentes, tokens de validación anti-CSRF y configuración de políticas SameSite en cookies.",
        "keywords": ["csrf", "cross-site request forgery", "ataque web", "manipulacion de parametros de seguridad"],
    },
    {
        "id": 14,
        "nombre": "Amenazas internas",
        "definicion": "Riesgos originados por individuos que poseen acceso legítimo a la infraestructura de una organización.",
        "riesgo": "El conocimiento de los sistemas internos permite eludir defensas o extraer información sensible de manera directa.",
        "prevencion": "Aplicación del principio de mínimo privilegio y uso de autenticación de múltiples factores (MFA) con componente físico.",
        "keywords": ["amenaza interna", "insider threat", "empleado", "cuenta de servicio", "acceso legitimo indebido"],
    },
    {
        "id": 15,
        "nombre": "Caballos de Troya",
        "definicion": "Software malicioso que se oculta dentro de un programa legítimo y aparentemente inofensivo. Al ejecutarse, abre una puerta trasera para que los atacantes se infiltren.",
        "riesgo": "Infiltración remota persistente en el sistema o red mediante una puerta trasera.",
        "prevencion": "Restringir descargas a orígenes verificados y usar firewalls de próxima generación (NGFW) para inspeccionar los paquetes de datos.",
        "keywords": ["troyano", "trojan", "puerta trasera", "backdoor"],
    },
    {
        "id": 16,
        "nombre": "Ataques de tipo drive-by",
        "definicion": "Inyección de código malicioso en sitios web inseguros que se ejecuta de forma automática al visitarlos, sin necesidad de que el usuario haga clic o ingrese datos.",
        "riesgo": "Infección inmediata del equipo del usuario con solo visitar el sitio comprometido.",
        "prevencion": "Mantener todo el software y complementos del sistema actualizados, y emplear herramientas de filtrado web.",
        "keywords": ["drive-by", "drive by download", "descarga automatica maliciosa"],
    },
    {
        "id": 17,
        "nombre": "Ataques de XSS (Secuencias de comandos entre sitios)",
        "definicion": "Inyección de scripts maliciosos en contenido web interactivo aprovechando una sesión activa y legítima del usuario.",
        "riesgo": "Manipulación de acciones del usuario, como alterar montos o destinatarios en transferencias bancarias en línea.",
        "prevencion": "Implementar listas blancas de entradas permitidas en las aplicaciones web y aplicar técnicas de desinfección de datos.",
        "keywords": ["xss", "cross-site scripting", "secuencias de comandos entre sitios", "script malicioso inyectado"],
    },
    {
        "id": 18,
        "nombre": "Ataques de espionaje (Eavesdropping)",
        "definicion": "Interceptación del tráfico de red para capturar credenciales y datos confidenciales, de forma activa (insertando software en la ruta) o pasiva (escuchando transmisiones). Es un tipo de ataque MITM.",
        "riesgo": "Robo de información confidencial en tránsito.",
        "prevencion": "Cifrar estrictamente todos los datos transmitidos por la red.",
        "keywords": ["eavesdropping", "espionaje de trafico", "espionaje de tráfico", "escucha de red", "sniffing"],
    },
    {
        "id": 19,
        "nombre": "Ataque de cumpleaños",
        "definicion": "Explotación de los algoritmos hash basados en la paradoja matemática del cumpleaños, para duplicar una firma digital idéntica y sustituir un mensaje legítimo por uno fraudulento sin ser detectado.",
        "riesgo": "Sustitución de un mensaje o firma legítima por una versión fraudulenta indetectable.",
        "prevencion": "Utilizar funciones hash con longitudes de caracteres superiores para reducir la probabilidad matemática de coincidencia.",
        "keywords": ["ataque de cumpleaños", "birthday attack", "colision de hash", "colisión de hash"],
    },
    {
        "id": 20,
        "nombre": "Ataque de malware",
        "definicion": "Término genérico para cualquier software malicioso diseñado para alterar el funcionamiento de un sistema, destruir información o espiar. Actúa como componente técnico ejecutor en múltiples ciberataques (troyanos, ransomware, drive-by, etc.).",
        "riesgo": "Alteración del sistema, destrucción de información o espionaje, según la carga maliciosa concreta.",
        "prevencion": "Combinar firewalls avanzados con capacitación constante de los usuarios sobre enlaces, descargas y correos sospechosos.",
        "keywords": ["malware", "malware_detectado", "software malicioso", "virus detectado"],
    },
    # -----------------------------------------------------------------------
    # Ids 21-30: investigados en julio de 2026 (Fortinet, Check Point, IBM,
    # Panorays, OWASP Top 10:2025) para cubrir el panorama actual que el
    # listado clásico de arriba no recoge -- ver CLAUDE.md para las fuentes
    # completas de esta ronda.
    # -----------------------------------------------------------------------
    {
        "id": 21,
        "nombre": "Ataques a la cadena de suministro",
        "definicion": "Compromiso de proveedores, dependencias de código abierto, integraciones de identidad, flujos de CI/CD o interfaces cloud de confianza, en vez de atacar directamente a la organización objetivo.",
        "riesgo": "Los incidentes de cadena de suministro se han multiplicado en los últimos años; un único proveedor comprometido puede exponer a todos sus clientes a la vez.",
        "prevencion": "Auditar a proveedores y dependencias críticas, verificar la procedencia de paquetes de terceros, y aplicar el mismo principio de mínimo privilegio a integraciones externas que a empleados.",
        "keywords": ["cadena de suministro", "supply chain", "proveedor comprometido", "dependencia comprometida", "ci/cd comprometido"],
    },
    {
        "id": 22,
        "nombre": "Ingeniería social potenciada por IA",
        "definicion": "Uso de IA generativa para crear deepfakes de voz o vídeo, clonar identidades de directivos en videollamadas, o generar campañas de phishing personalizadas a gran escala sin los errores gramaticales que antes delataban el fraude.",
        "riesgo": "Los ataques de ingeniería social son ahora indistinguibles de una comunicación legítima; un deepfake de voz del CEO puede autorizar una transferencia fraudulenta en tiempo real.",
        "prevencion": "Establecer un segundo canal de verificación (llamada a un número ya conocido, no al que aparece en el mensaje) para cualquier instrucción financiera o urgente, sin excepciones por jerarquía.",
        "keywords": ["deepfake", "voz clonada", "ia generativa", "videollamada suplantada", "clonacion de voz", "clonación de voz"],
    },
    {
        "id": 23,
        "nombre": "Configuraciones erróneas en la nube",
        "definicion": "Buckets de almacenamiento, bases de datos o paneles de administración expuestos públicamente por error, permisos IAM demasiado amplios, o modelos de responsabilidad compartida mal entendidos entre proveedor y cliente cloud.",
        "riesgo": "Es la categoría de riesgo que más ha subido en el ranking OWASP 2025 (de 5º a 2º puesto); el multi-cloud ha superado la capacidad de muchas organizaciones para vigilar y asegurar sus propios entornos.",
        "prevencion": "Escaneo continuo de configuración cloud (CSPM), revisión periódica de permisos IAM, y nunca asumir que el proveedor cloud cubre una responsabilidad que en realidad es del cliente.",
        "keywords": ["configuracion erronea", "configuración errónea en la nube", "bucket expuesto", "cloud misconfiguration", "permisos iam", "panel expuesto publicamente"],
    },
    {
        "id": 24,
        "nombre": "Ataques a APIs",
        "definicion": "Explotación de fallos de autorización a nivel de objeto, ausencia de límites de tasa (rate limiting), o exposición excesiva de datos en endpoints de API, a menudo saltándose la autenticación multifactor de la aplicación que los envuelve.",
        "riesgo": "Las APIs son el vector de entrada en la gran mayoría de brechas en aplicaciones cloud-native, precisamente porque suelen tener menos controles que la interfaz de usuario que las consume.",
        "prevencion": "Aplicar el OWASP API Security Top 10: autorización a nivel de objeto en cada endpoint, límites de tasa, y validación estricta de todo dato de entrada, no solo el que llega desde el frontend oficial.",
        "keywords": ["ataque a api", "api attack", "broken object level authorization", "rate limiting", "endpoint expuesto"],
    },
    {
        "id": 25,
        "nombre": "Relleno de credenciales (Credential Stuffing)",
        "definicion": "Uso automatizado de listas de usuario/contraseña filtradas en brechas de otros servicios, probándolas masivamente contra un servicio distinto -- distinto de la fuerza bruta porque no adivina, reutiliza credenciales ya robadas en otro sitio.",
        "riesgo": "Funciona porque una gran parte de los usuarios reutiliza la misma contraseña en varios servicios; un solo login válido puede bastar para acceder a cuentas corporativas.",
        "prevencion": "Exigir MFA en todo acceso externo, comprobar contraseñas contra listas de credenciales filtradas conocidas, y limitar/bloquear patrones de login automatizado desde IPs o user-agents anómalos.",
        "keywords": ["credential stuffing", "relleno de credenciales", "credenciales filtradas", "reutilizacion de contraseñas", "login automatizado masivo"],
    },
    {
        "id": 26,
        "nombre": "Cryptojacking",
        "definicion": "Instalación encubierta de software de minado de criptomonedas en sistemas, contenedores o recursos cloud comprometidos, aprovechando su capacidad de cómputo sin autorización.",
        "riesgo": "Degradación del rendimiento y facturas cloud disparadas; suele ser el síntoma visible de un compromiso más profundo que ya tiene acceso al sistema.",
        "prevencion": "Monitorizar el uso anómalo de CPU/GPU y de facturación cloud, y aplicar los mismos controles de acceso que para cualquier otro malware (los recursos comprometidos casi siempre llegaron por otra vía ya conocida).",
        "keywords": ["cryptojacking", "minado de criptomonedas", "consumo anomalo de cpu", "consumo anómalo de cpu", "mineria no autorizada"],
    },
    {
        "id": 27,
        "nombre": "Ataques contra sistemas de IA",
        "definicion": "Inyección de prompts maliciosos, envenenamiento de datos de entrenamiento, extracción del modelo, o secuestro de agentes autónomos de IA para que ejecuten acciones no previstas por quien los desplegó.",
        "riesgo": "Los incidentes de seguridad relacionados con IA han crecido con fuerza a medida que más organizaciones despliegan agentes autónomos con permisos reales sobre sistemas de producción.",
        "prevencion": "Tratar cualquier entrada a un sistema de IA (incluido contenido de terceros que el modelo pueda leer) como no confiable, limitar los permisos reales que un agente puede ejecutar sin confirmación humana, y auditar sus decisiones igual que las de un empleado nuevo.",
        "keywords": ["prompt injection", "inyeccion de prompt", "envenenamiento de datos", "secuestro de agente", "modelo de ia comprometido", "agente autonomo comprometido"],
    },
    {
        "id": 28,
        "nombre": "Compromiso de correo corporativo (BEC)",
        "definicion": "Fraude dirigido específicamente a iniciar transferencias bancarias o pagos fraudulentos, mediante una cuenta de correo corporativo real comprometida o un dominio visualmente casi idéntico -- distinto del whaling en que el objetivo es siempre el fraude económico directo, no el robo de datos.",
        "riesgo": "Pérdida económica directa e inmediata; al usar una cuenta o dominio casi indistinguible del legítimo, suele evadir los filtros de phishing estándar.",
        "prevencion": "Doble verificación obligatoria (fuera del correo) para cualquier cambio de cuenta bancaria o pago no habitual, y DMARC/DKIM/SPF correctamente configurados en el dominio corporativo.",
        "keywords": ["bec", "business email compromise", "compromiso de correo corporativo", "cambio de cuenta bancaria", "transferencia urgente solicitada por correo", "dominio casi identico"],
    },
    {
        "id": 29,
        "nombre": "Secuestro de SIM (SIM Swapping)",
        "definicion": "Transferencia fraudulenta de un número de teléfono a una tarjeta SIM controlada por el atacante, habitualmente mediante ingeniería social contra el operador móvil, para interceptar los códigos de verificación SMS.",
        "riesgo": "Permite saltarse la autenticación multifactor basada en SMS y tomar control de cuentas (bancarias, corporativas, redes sociales) que dependen de ese número como recuperación.",
        "prevencion": "Usar aplicaciones de autenticación (TOTP) o llaves físicas en vez de SMS para MFA, y activar el PIN/bloqueo anti-portabilidad que ofrecen los operadores móviles.",
        "keywords": ["sim swapping", "secuestro de sim", "duplicado de sim", "portabilidad fraudulenta", "codigo sms interceptado"],
    },
    {
        "id": 30,
        "nombre": "Botnets de IoT",
        "definicion": "Redes de dispositivos IoT comprometidos (cámaras, routers domésticos, sensores) con credenciales por defecto o firmware sin actualizar, controlados de forma remota para lanzar ataques DDoS masivos u otras operaciones a gran escala.",
        "riesgo": "El volumen de dispositivos IoT mal asegurados permite construir botnets enormes con muy poco esfuerzo, y rara vez el propietario del dispositivo comprometido se entera.",
        "prevencion": "Cambiar credenciales por defecto en todo dispositivo IoT, mantener firmware actualizado, y segmentar la red para que los dispositivos IoT no tengan acceso directo a sistemas críticos.",
        "keywords": ["botnet iot", "dispositivo iot comprometido", "credenciales por defecto", "firmware sin actualizar", "camara comprometida", "router comprometido"],
    },
    # ---- WAAP (H1 híbrido: Cloudflare + Coraza on-prem) ----
    # Añadidas 2026-08-01 al incorporar la ingesta WAF. No dupliqué SQLi/XSS/
    # DDoS/credential stuffing porque ya estaban (ids 8, 17, 1, 25) y sus
    # keywords casan con el vocabulario Cloudflare/OWASP CRS tal cual. Faltaba
    # el reconocimiento activo (bots/scanners) — T1595 no estaba mapeado — y
    # el path traversal / LFI, que un WAF lo señala aparte de un SQLi.
    {
        "id": 31,
        "nombre": "Escaneo activo y bots maliciosos",
        "definicion": "Sondeos automáticos de puertos, rutas o vulnerabilidades desde bots o herramientas de reconocimiento (nikto, sqlmap, nmap, scanners de vulnerabilidades) antes de un ataque real. Un WAAP los detecta por firma del cliente, patrones de URL probadas y volumen.",
        "riesgo": "Fase previa a la explotación: si se ignora, el atacante mapea la superficie de ataque y vuelve con un exploit dirigido. También revela credenciales y endpoints ocultos que el sitio no debía exponer.",
        "prevencion": "Bot Management en la capa cloud (Cloudflare Bot Fight Mode o similar), reglas de rate limiting por IP/ASN, y bloqueo de user-agents de herramientas conocidas en el WAAP on-prem.",
        # "scanner" (sin "-ing") añadido 2026-09-04: es el valor literal que
        # produce siem/ingest/cloudflare.py::_SOURCE_TO_CATEGORY para
        # botFight/bic/hot -- "scanning" nunca es substring de "scanner", así
        # que ninguna detección de bot/escáner de Cloudflare casaba con esta
        # entrada y el kill-chain salía vacío para ese tráfico.
        "keywords": ["scanning", "scanner", "escaneo activo", "sqlmap", "nikto", "nmap", "bot malicioso", "reconocimiento", "vulnerability scanner", "bad bot", "crawler malicioso"],
    },
    {
        "id": 32,
        "nombre": "Path traversal / Inclusión de ficheros (LFI/RFI)",
        "definicion": "Manipulación de rutas en peticiones HTTP con secuencias tipo `../../etc/passwd` o rutas absolutas para leer ficheros del servidor fuera del directorio permitido, o incluir código remoto en el flujo de la app.",
        "riesgo": "Lectura de ficheros sensibles del servidor (configuración, claves, código fuente) sin necesidad de autenticación, y en RFI ejecución de código controlado por el atacante.",
        "prevencion": "Validar y canonicalizar rutas en el servidor, deshabilitar `allow_url_include` en PHP, y habilitar las reglas OWASP CRS 930xxx (LFI) y 931xxx (RFI) en el WAAP.",
        # Rutas de disclosure de ficheros sensibles añadidas 2026-09-04: son
        # el grueso real del tráfico WAF bloqueado (wp-config.php, .env,
        # .git/HEAD, claves SSH/AWS...) y encajan con la definición de esta
        # entrada, pero no casaban con ningún keyword existente -- el summary
        # del evento SÍ incluye la ruta (waf.py::_to_event), así que basta con
        # sumarlas aquí sin tocar el clasificador.
        "keywords": ["path traversal", "directory traversal", "lfi", "local file inclusion", "rfi", "remote file inclusion", "../", "etc/passwd", "traversal", "wp-config", ".env", ".git/head", ".ssh/authorized_keys", ".aws/credentials", "key.json", "values.yaml", ".swp", ".swo", "@fs/"],
    },
    {
        "id": 33,
        "nombre": "Ejecución remota de código (RCE)",
        "definicion": "Explotación de una vulnerabilidad (a menudo con CVE público) que permite al atacante ejecutar comandos o código arbitrario en el servidor a través de una petición HTTP manipulada -- deserialización insegura, inyección de comandos, plantillas server-side, etc.",
        "riesgo": "El impacto más alto de los ataques web: control total del proceso/servidor, no solo lectura de datos. Suele ser el paso previo a instalar un backdoor o moverse lateralmente.",
        "prevencion": "Parchear con prioridad cualquier CVE de RCE conocido en el stack, WAF con reglas OWASP CRS 932xxx/933xxx activas, y ejecutar la aplicación con el mínimo privilegio posible para limitar el impacto si la explotación tiene éxito.",
        # Añadida 2026-09-04: siem/ingest/cloudflare.py ya clasificaba ataques
        # como categoría "rce" (keywords "remote code execution"/"command
        # injection" en la descripción de Cloudflare) desde que se incorporó
        # el WAF, pero nunca hubo entrada de catálogo que lo recogiera -- todo
        # bloqueo de RCE real (el caso más grave) se quedaba sin threat_id y
        # por tanto sin paso en el kill-chain.
        "keywords": ["rce", "remote code execution", "ejecucion remota de codigo", "ejecución remota de código", "command injection", "inyeccion de comandos", "inyección de comandos", "deserialization", "deserializacion insegura", "cve:", "ssti", "server-side template injection"],
    },
]

# ===========================================================================
# Mapa a MITRE ATT&CK — la "capa de vocabulario" que convierte una amenaza
# suelta del catálogo en un paso de una cadena de ataque (kill-chain).
#
# Por qué una tabla aparte y no un campo más en cada dict de arriba:
#   1. El literal de 30 entradas ya es grande; meter 4 campos ATT&CK en cada
#      uno multiplica el ruido y el riesgo de erratas al editarlo.
#   2. El mapeo amenaza -> táctica/técnica es EXACTAMENTE lo que un analista
#      querrá auditar y discutir de un vistazo. Aquí está todo junto, en una
#      sola tabla revisable, en la misma línea determinista que
#      `threat_detection.py` (reglas visibles, no inferencia de IA).
#   3. Se inyecta en cada entrada al cargar el módulo, así que a partir de
#      `get_threat(id)` los campos ya vienen incluidos y transparentes.
#
# Cada amenaza se mapea a UNA táctica + técnica primaria (MVP). Una amenaza
# real puede tocar varias tácticas, pero una principal basta para ordenar la
# cadena y narrarla; ampliar a lista es un cambio local a esta tabla.
#
# Nomenclatura: tácticas/técnicas de MITRE ATT&CK Enterprise
# (https://attack.mitre.org/). Las dos entradas de IA (27) usan un id de
# MITRE ATLAS (AML.*) porque ATT&CK Enterprise no cubre aún prompt injection;
# se etiqueta explícito para no mezclar marcos sin avisar.
# ---------------------------------------------------------------------------

# Orden canónico de la kill-chain de ATT&CK. Sirve para ordenar los pasos de
# un incidente de "cómo empezó" a "qué impacto tuvo" al narrarlo.
TACTIC_ORDER: dict[str, int] = {
    "TA0043": 0,   # Reconnaissance / Reconocimiento
    "TA0042": 1,   # Resource Development / Desarrollo de recursos
    "TA0001": 2,   # Initial Access / Acceso inicial
    "TA0002": 3,   # Execution / Ejecución
    "TA0003": 4,   # Persistence / Persistencia
    "TA0004": 5,   # Privilege Escalation / Escalada de privilegios
    "TA0005": 6,   # Defense Evasion / Evasión de defensas
    "TA0006": 7,   # Credential Access / Acceso a credenciales
    "TA0007": 8,   # Discovery / Descubrimiento
    "TA0008": 9,   # Lateral Movement / Movimiento lateral
    "TA0009": 10,  # Collection / Recolección
    "TA0011": 11,  # Command and Control / Mando y control
    "TA0010": 12,  # Exfiltration / Exfiltración
    "TA0040": 13,  # Impact / Impacto
}

# Nombre legible (en español) de cada táctica, para la narrativa y los paneles.
TACTIC_NAME_ES: dict[str, str] = {
    "TA0043": "Reconocimiento",
    "TA0042": "Desarrollo de recursos",
    "TA0001": "Acceso inicial",
    "TA0002": "Ejecución",
    "TA0003": "Persistencia",
    "TA0004": "Escalada de privilegios",
    "TA0005": "Evasión de defensas",
    "TA0006": "Acceso a credenciales",
    "TA0007": "Descubrimiento",
    "TA0008": "Movimiento lateral",
    "TA0009": "Recolección",
    "TA0011": "Mando y control (C2)",
    "TA0010": "Exfiltración",
    "TA0040": "Impacto",
}

# threat_id -> (tactic_id, technique_id, technique_name)
# El nombre de la táctica se resuelve por TACTIC_NAME_ES para no repetirlo.
_MITRE_RAW: dict[int, tuple[str, str, str]] = {
    1:  ("TA0040", "T1498",       "Denegación de servicio de red"),
    2:  ("TA0009", "T1557",       "Adversario en el medio (AiTM)"),
    3:  ("TA0001", "T1566",       "Phishing"),
    4:  ("TA0001", "T1566",       "Phishing (whaling / directivos)"),
    5:  ("TA0001", "T1566",       "Phishing dirigido (spearphishing)"),
    6:  ("TA0040", "T1486",       "Datos cifrados para impacto"),
    7:  ("TA0006", "T1110",       "Fuerza bruta / adivinación de credenciales"),
    8:  ("TA0001", "T1190",       "Explotación de aplicación pública"),
    9:  ("TA0001", "T1190",       "Explotación de aplicación pública"),
    10: ("TA0006", "T1557",       "Adversario en el medio: suplantación DNS"),
    11: ("TA0006", "T1539",       "Robo de cookie de sesión web"),
    12: ("TA0006", "T1110",       "Fuerza bruta"),
    13: ("TA0001", "T1190",       "Explotación de aplicación pública"),
    14: ("TA0001", "T1078",       "Cuentas válidas (uso indebido interno)"),
    15: ("TA0002", "T1204",       "Ejecución por el usuario (archivo malicioso)"),
    16: ("TA0001", "T1189",       "Compromiso drive-by"),
    17: ("TA0001", "T1190",       "Explotación de aplicación pública (XSS)"),
    18: ("TA0006", "T1040",       "Rastreo de red (sniffing)"),
    19: ("TA0005", "T1600",       "Debilitamiento del cifrado"),
    20: ("TA0002", "T1204",       "Ejecución por el usuario"),
    21: ("TA0001", "T1195",       "Compromiso de la cadena de suministro"),
    22: ("TA0001", "T1566",       "Phishing (ingeniería social con IA / deepfake)"),
    23: ("TA0001", "T1190",       "Explotación de aplicación pública (config. cloud)"),
    24: ("TA0001", "T1190",       "Explotación de aplicación pública (API)"),
    25: ("TA0006", "T1110.004",   "Relleno de credenciales"),
    26: ("TA0040", "T1496",       "Secuestro de recursos"),
    27: ("TA0001", "AML.T0051",   "Inyección de prompt (MITRE ATLAS)"),
    28: ("TA0001", "T1566",       "Phishing (BEC / fraude de correo)"),
    29: ("TA0006", "T1111",       "Interceptación de MFA (SIM swapping)"),
    30: ("TA0040", "T1498",       "Denegación de servicio de red (botnet IoT)"),
    31: ("TA0007", "T1595",       "Escaneo activo (reconocimiento)"),
    32: ("TA0001", "T1190",       "Explotación de aplicación pública (LFI/RFI)"),
    33: ("TA0001", "T1190",       "Explotación de aplicación pública (RCE)"),
}

# Inyecta los campos MITRE en cada entrada del catálogo. Si en algún momento
# se añade una amenaza sin mapear en `_MITRE_RAW`, esto falla en carga (no en
# silencio): preferimos un error explícito a un incidente sin táctica.
for _t in THREATS_CATALOG:
    _tid = _t["id"]
    if _tid not in _MITRE_RAW:
        raise RuntimeError(
            f"Amenaza id={_tid} ('{_t['nombre']}') sin mapeo MITRE en _MITRE_RAW"
        )
    _tactic_id, _tech_id, _tech_name = _MITRE_RAW[_tid]
    _t["mitre_tactic_id"] = _tactic_id
    _t["mitre_tactic"] = TACTIC_NAME_ES[_tactic_id]
    _t["mitre_technique_id"] = _tech_id
    _t["mitre_technique"] = _tech_name


THREATS_BY_ID: dict[int, ThreatEntry] = {t["id"]: t for t in THREATS_CATALOG}


def get_threat(threat_id: int) -> Optional[ThreatEntry]:
    return THREATS_BY_ID.get(threat_id)


def list_threats() -> list[ThreatEntry]:
    return THREATS_CATALOG


def tactic_rank(tactic_id: str) -> int:
    """Posición de una táctica en la kill-chain de ATT&CK. Las desconocidas
    van al final (999) para que ordenar nunca reviente por un id inesperado."""
    return TACTIC_ORDER.get(tactic_id, 999)
