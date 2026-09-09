"""Datos de ejemplo para /demo/dashboard (2026-09-04).

Sembrado una sola vez -- si `siam_demo.db` ya tiene incidentes (arranque
anterior), no repite -- en una base de datos SEPARADA de la real (ver
`siem/router/demo.py`, que apunta todas las rutas `/demo/v1/*` a esta base
vía `get_demo_store`). Un visitante anónimo de `/demo/dashboard` nunca ve
ni puede tocar datos de cliente reales: solo estos incidentes inventados.

Los eventos y timelines están hechos a mano (no vía `correlate_event`) a
propósito, para que la demo muestre siempre la misma historia curada en vez
de lo que el motor de correlación decida generar.
"""
import datetime as dt
import random

from siem.models import (
    IOC,
    Asset,
    AssetCriticality,
    Event,
    Incident,
    IncidentStatus,
    Severity,
    TimelineEntry,
)
from siem.store import SiemStore


def seed_demo_data(store: SiemStore) -> None:
    if store.list_incidents():
        return

    now = dt.datetime.utcnow()

    web = store.add_asset(
        Asset(name="srv-web-01", type="servidor", criticality=AssetCriticality.ALTA, owner="Equipo IT")
    )
    fw = store.add_asset(
        Asset(name="fw-perimetral", type="red", criticality=AssetCriticality.CRITICA, owner="Equipo IT")
    )
    laptop = store.add_asset(
        Asset(name="laptop-direccion", type="endpoint", criticality=AssetCriticality.MEDIA, owner="Dirección")
    )
    db_clientes = store.add_asset(
        Asset(name="db-clientes", type="cloud", criticality=AssetCriticality.CRITICA, owner="Equipo IT")
    )

    # Ruido de fondo para el gráfico "ataques a lo largo del tiempo": ~60
    # eventos repartidos en los últimos 14 días, mayoría benignos.
    rng = random.Random(4)
    assets = [web, fw, laptop, db_clientes]
    sources = ["firewall", "edr", "cloud", "waf"]
    for _ in range(60):
        ts = now - dt.timedelta(hours=rng.randint(0, 14 * 24))
        sev = rng.choices(
            [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
            weights=[40, 25, 20, 10, 5],
        )[0]
        asset = rng.choice(assets)
        store.add_event(
            Event(
                source=rng.choice(sources),
                asset_id=asset.id,
                asset_name=asset.name,
                event_type="trafico",
                severity=sev,
                summary="Tráfico anómalo detectado" if sev != Severity.INFO else "Evento de rutina",
                timestamp=ts,
            )
        )

    # --- Incidente 1: ransomware, crítico, en investigación ---
    inc1 = Incident(
        title="Ransomware detectado en srv-web-01",
        severity=Severity.CRITICAL,
        status=IncidentStatus.EN_INVESTIGACION,
        description=(
            "El EDR detectó cifrado masivo de ficheros y un proceso sospechoso "
            "(svhost32.exe) en srv-web-01."
        ),
        affected_assets=[web.id],
        risk_score=92,
        recommendations=[
            "Aislar el activo de la red",
            "Restaurar desde backup 3-2-1 verificado",
            "Rotar credenciales del servicio afectado",
        ],
        evidence=[
            "Hash del binario: 8f14e45fceea167a5a36dedd4bea2543",
            "IP C2 contactada: 185.220.101.7",
        ],
        timeline=[
            TimelineEntry(actor="EDR", description="Proceso svhost32.exe detectado cifrando /var/www"),
            TimelineEntry(actor="SOC", description="Incidente escalado a crítico, aislamiento de red iniciado"),
        ],
        # threat_ids (catálogo, ver siem/threats_catalog.py): 16=drive-by
        # (acceso inicial), 20=malware (ejecución), 6=ransomware (impacto) --
        # con esto /kill-chain reconstruye una cadena de 3 pasos real en vez
        # de salir vacía (build_kill_chain solo lee threat_ids de los EVENTOS,
        # ver abajo; aquí es solo el resumen a nivel de incidente).
        threat_ids=[16, 20, 6],
        created_at=now - dt.timedelta(hours=6),
        updated_at=now - dt.timedelta(hours=1),
    )
    store.add_incident(inc1)
    store.add_event(
        Event(
            source="edr", asset_id=web.id, asset_name=web.name, event_type="drive-by",
            severity=Severity.HIGH, summary="Descarga silenciosa desde sitio comprometido",
            incident_id=inc1.id, threat_ids=[16], timestamp=now - dt.timedelta(hours=6, minutes=10),
        )
    )
    store.add_event(
        Event(
            source="edr", asset_id=web.id, asset_name=web.name, event_type="malware",
            severity=Severity.CRITICAL, summary="Proceso svhost32.exe ejecutado por el usuario",
            incident_id=inc1.id, threat_ids=[20], timestamp=now - dt.timedelta(hours=6),
        )
    )
    store.add_event(
        Event(
            source="edr", asset_id=web.id, asset_name=web.name, event_type="ransomware",
            severity=Severity.CRITICAL, summary="Cifrado masivo de ficheros detectado",
            incident_id=inc1.id, threat_ids=[6], timestamp=now - dt.timedelta(hours=5, minutes=55),
        )
    )
    store.add_event(
        Event(
            source="firewall", asset_id=web.id, asset_name=web.name, event_type="c2",
            severity=Severity.CRITICAL, summary="Conexión saliente a IP de C2 conocida",
            incident_id=inc1.id, timestamp=now - dt.timedelta(hours=5, minutes=50),
        )
    )

    # --- Incidente 2: fuerza bruta SSH, alto, abierto ---
    inc2 = Incident(
        title="Múltiples intentos de fuerza bruta SSH",
        severity=Severity.HIGH,
        status=IncidentStatus.ABIERTO,
        description="fw-perimetral registró 340 intentos de login fallidos contra el puerto 22 en 10 minutos.",
        affected_assets=[fw.id],
        risk_score=68,
        recommendations=["Bloquear la IP de origen", "Activar fail2ban / rate limiting en el firewall"],
        timeline=[TimelineEntry(actor="Firewall", description="340 intentos fallidos desde 91.243.x.x en 10 minutos")],
        threat_ids=[12],
        created_at=now - dt.timedelta(hours=2),
        updated_at=now - dt.timedelta(hours=2),
    )
    store.add_incident(inc2)
    store.add_event(
        Event(
            source="firewall", asset_id=fw.id, asset_name=fw.name, event_type="bruteforce",
            severity=Severity.HIGH, summary="340 intentos de login SSH fallidos",
            incident_id=inc2.id, threat_ids=[12], timestamp=now - dt.timedelta(hours=2),
        )
    )

    # --- Incidente 3: phishing, medio, resuelto ---
    inc3 = Incident(
        title="Phishing dirigido a Dirección",
        severity=Severity.MEDIUM,
        status=IncidentStatus.RESUELTO,
        description=(
            "Email con enlace de credential harvesting recibido en laptop-direccion; "
            "el usuario reportó el correo sin hacer clic."
        ),
        affected_assets=[laptop.id],
        risk_score=35,
        recommendations=["Formación de concienciación reforzada", "Bloquear el dominio remitente"],
        timeline=[
            TimelineEntry(actor="Usuario", description="Correo sospechoso reportado desde el cliente de correo"),
            TimelineEntry(actor="SOC", description="Dominio remitente bloqueado, incidente cerrado"),
        ],
        threat_ids=[3],
        created_at=now - dt.timedelta(days=2),
        updated_at=now - dt.timedelta(days=1, hours=20),
        resolved_at=now - dt.timedelta(days=1, hours=20),
    )
    store.add_incident(inc3)
    store.add_event(
        Event(
            source="manual", asset_id=laptop.id, asset_name=laptop.name, event_type="phishing",
            severity=Severity.MEDIUM, summary="Correo de phishing reportado por el usuario",
            incident_id=inc3.id, threat_ids=[3], timestamp=now - dt.timedelta(days=2),
        )
    )

    # --- Eventos WAF/honeypot inventados, para el dashboard "📊 Métricas de
    # ataques" (ATTACK_SOURCES en siem/active_defense.py = WAF + honeypot).
    # raw_payload replica el formato de siem/router/waf.py::_to_event -- es
    # lo que lee siem/store.py::attack_metrics() para el desglose por
    # severidad/categoría/país/serie temporal. Un prospecto que abra la demo
    # debe ver un dashboard con datos, no en ceros.
    _WAF_ATTACKERS = [
        ("203.0.113.9", "RU", "AS64500", "sqli", Severity.CRITICAL),
        ("198.51.100.23", "CN", "AS64501", "xss", Severity.HIGH),
        ("198.51.100.77", "CN", "AS64501", "rce", Severity.CRITICAL),
        ("192.0.2.14", "BR", "AS64502", "lfi", Severity.HIGH),
        ("192.0.2.55", "VN", "AS64503", "generic", Severity.MEDIUM),
        ("203.0.113.201", "NG", "AS64504", "sqli", Severity.MEDIUM),
        ("203.0.113.240", "RU", "AS64500", "scan", Severity.LOW),
    ]
    for ip, country, asn, category, base_sev in _WAF_ATTACKERS:
        n_events = rng.randint(3, 14)
        for _ in range(n_events):
            ts = now - dt.timedelta(hours=rng.randint(0, 13 * 24))
            sev = rng.choice([base_sev, base_sev, Severity.MEDIUM])
            store.add_event(
                Event(
                    source="waf-cloudflare",
                    event_type=f"waf.block.{category}",
                    severity=sev,
                    summary=f"WAF BLOCK {category} desde {ip} ({country})",
                    timestamp=ts,
                    raw_payload={
                        "client_ip": ip, "country": country, "asn": asn,
                        "attack_category": category, "action": "block",
                        "host": "web-prod-01", "uri": "/wp-login.php" if category == "generic" else "/api/login",
                        "user_agent": "python-requests/2.31" if category == "scan" else "Mozilla/5.0",
                    },
                )
            )

    # Un par de IPs que además tocan el honeypot (ver siem/router/honeypot.py)
    # -- interacción posterior a caer en el señuelo, cuenta aparte en
    # attack_metrics() como "honeypot_interactions".
    for ip, country in [("198.51.100.77", "CN"), ("203.0.113.9", "RU")]:
        for _ in range(rng.randint(2, 6)):
            ts = now - dt.timedelta(hours=rng.randint(0, 10 * 24))
            store.add_event(
                Event(
                    source="honeypot",
                    event_type="honeypot.interaction",
                    severity=Severity.LOW,
                    summary=f"Interacción con honeypot desde {ip} ({country})",
                    timestamp=ts,
                    raw_payload={"client_ip": ip, "country": country, "attack_category": "recon"},
                )
            )

    # IP ya bloqueada de ejemplo -- para que "IPs bloqueadas" del dashboard
    # de métricas no salga siempre a cero.
    store.add_ioc(IOC(type="ip", value="203.0.113.9", confidence="alta", action="BLOCK"))
