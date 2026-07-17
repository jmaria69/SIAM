"""Tests del simulador de crisis: siem/scenarios.py (biblioteca) y
siem/simulator.py (motor).

La inyección de un paso (_inject_step) se testea de forma síncrona y
directa, sin asyncio.sleep, contra una base en memoria propia de este
archivo -- así verificamos que el paso persiste el evento y dispara la
correlación de verdad, sin depender de esperar los delays reales del
escenario (eso además rompería el objetivo de que los tests sean rápidos,
el mismo motivo por el que el proveedor de IA se aísla en conftest.py).

La parte HTTP (arrancar/consultar una ejecución) vive en
test_incidents.py-style, contra el `client` de conftest.py, pero sin
esperar tampoco a que el escenario termine -- eso sí depende de tiempo
real y no es lo que se quiere verificar aquí.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from siem.database import Base
from siem.scenarios import get_scenario, list_scenarios
from siem.simulator import _inject_step
from siem.store import SiemStore

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_Session = sessionmaker(bind=_engine)


def setup_function(_):
    Base.metadata.create_all(bind=_engine)


def teardown_function(_):
    Base.metadata.drop_all(bind=_engine)


def _new_run(scenario_id: str) -> dict:
    return {
        "run_id": "SIM-test0001",
        "scenario_id": scenario_id,
        "status": "en_curso",
        "completed_steps": 0,
        "log": [],
    }


def test_all_scenarios_have_at_least_one_step():
    for scenario in list_scenarios():
        assert len(scenario.steps) > 0


def test_get_scenario_unknown_returns_none():
    assert get_scenario("no-existe") is None


def test_inject_step_persists_event_and_correlates():
    scenario = get_scenario("ransomware")
    db = _Session()
    store = SiemStore(db)
    run = _new_run(scenario.id)
    try:
        for step in scenario.steps:
            _inject_step(store, run, step)

        assert run["completed_steps"] == len(scenario.steps)
        assert len(run["log"]) == len(scenario.steps)
        assert all("event_id" in entry for entry in run["log"])

        events = store.list_events()
        assert len(events) == len(scenario.steps)

        incidents = store.list_incidents()
        # La correlación agrupa por activo dentro de la ventana de tiempo:
        # el escenario "ransomware" toca 3 activos distintos (web-prod-01,
        # db-prod-01, backup-01), así que debe haber menos incidentes que
        # eventos -- no uno por evento -- pero más de uno, no todos juntos.
        assert 0 < len(incidents) < len(events)
    finally:
        db.close()


def test_inject_step_marks_incident_id_on_event():
    scenario = get_scenario("fuga_datos")
    db = _Session()
    store = SiemStore(db)
    run = _new_run(scenario.id)
    try:
        for step in scenario.steps:
            event = _inject_step(store, run, step)
            assert event.incident_id is not None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Escenarios nuevos (2026-07-05) para las 10 amenazas investigadas en la
# ronda del catálogo de 30 (siem/threats_catalog.py). El objetivo aquí no es
# repetir test_threat_detection.py (que ya prueba detect_threats de forma
# aislada), sino confirmar que el vocabulario elegido en estos escenarios
# concretos SÍ dispara la detección esperada al pasar por el pipeline real
# -- si alguien reescribe el summary/description de un paso sin fijarse en
# las keywords del catálogo, uno de estos tests lo pilla.
# ---------------------------------------------------------------------------
SCENARIO_EXPECTED_THREAT_IDS = {
    "cadena_suministro": {21},
    "ingenieria_social_ia": {22, 28},
    "cryptojacking_cloud": {23, 26},
    "relleno_credenciales": {25},
    "botnet_iot_ddos": {30, 1},
    "api_ia_sim": {24, 27, 29},
}


def test_new_scenarios_are_registered():
    ids = {s.id for s in list_scenarios()}
    assert set(SCENARIO_EXPECTED_THREAT_IDS) <= ids


def test_new_scenarios_trigger_expected_threat_detection():
    for scenario_id, expected_ids in SCENARIO_EXPECTED_THREAT_IDS.items():
        scenario = get_scenario(scenario_id)
        db = _Session()
        store = SiemStore(db)
        run = _new_run(scenario.id)
        try:
            for step in scenario.steps:
                _inject_step(store, run, step)

            detected: set[int] = set()
            for incident in store.list_incidents():
                detected.update(incident.threat_ids)

            missing = expected_ids - detected
            assert not missing, f"{scenario_id}: no se detectaron los ids {missing}"
        finally:
            db.close()
            Base.metadata.drop_all(bind=_engine)
            Base.metadata.create_all(bind=_engine)


# ---------------------------------------------------------------------------
# Capa HTTP: arrancar/consultar una ejecución. Usa el `client` de
# conftest.py (misma base en memoria que el resto de tests). Deliberadamente
# NO se espera a que un escenario termine -- eso depende de los delays
# reales (varios segundos) y no es lo que se quiere verificar aquí; ese
# camino (persistencia + correlación paso a paso) ya está cubierto arriba
# de forma síncrona y rápida.
# ---------------------------------------------------------------------------
def test_list_scenarios_returns_known_ids(client):
    response = client.get("/v1/monitoring/scenarios")
    assert response.status_code == 200
    ids = {s["id"] for s in response.json()}
    assert {"ransomware", "phishing_ddos", "fuga_datos"} <= ids


def test_start_simulation_returns_run_metadata(client):
    response = client.post("/v1/monitoring/simulate/fuga_datos")
    assert response.status_code == 200
    data = response.json()
    assert data["scenario_id"] == "fuga_datos"
    assert data["total_steps"] == 3
    assert data["run_id"].startswith("SIM-")
    assert data["status"] in ("en_curso", "completado")


def test_start_simulation_unknown_scenario_returns_404(client):
    response = client.post("/v1/monitoring/simulate/no-existe")
    assert response.status_code == 404


def test_simulation_status_for_unknown_run_returns_404(client):
    response = client.get("/v1/monitoring/simulate/SIM-doesnotexist/status")
    assert response.status_code == 404


def test_simulation_status_reflects_started_run(client):
    start = client.post("/v1/monitoring/simulate/fuga_datos").json()
    status = client.get(f"/v1/monitoring/simulate/{start['run_id']}/status")
    assert status.status_code == 200
    assert status.json()["run_id"] == start["run_id"]
