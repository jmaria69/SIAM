"""Login + 2FA del dashboard real (siem/router/auth.py + siem/main.py).

Verifica que "/" y /v1/* quedan detrás de usuario + contraseña (scrypt) +
código TOTP cuando hay credenciales de admin configuradas -- misma idea que
praxialabs.com/admin -- y que la demo pública (/demo/*) y el honeypot
(/admin) siguen abiertos a propósito.

Mismo patrón que test_docs_gating.py / test_api_key_auth.py: app construida
con create_app(Settings(...)) porque los middlewares leen settings_ en tiempo
de request. Además hay que overridear get_settings() a los mismos valores,
porque las rutas de /login lo consumen vía Depends(get_settings) y en los
tests no queremos depender del .env real.
"""
import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from siem.auth import hash_password
from siem.config import Settings, get_settings
from siem.database import Base
from siem.main import create_app
from siem.router.demo import get_demo_store
from siem.store import SiemStore

TOTP_SECRET = pyotp.random_base32()
BASIC_AUTH = dict(
    SIAM_ADMIN_USERNAME="admin",
    SIAM_ADMIN_PASSWORD_HASH=hash_password("contraseña-super-segura-2026"),
    SIAM_ADMIN_TOTP_SECRET=TOTP_SECRET,
    SIAM_AUTH_SESSION_SECRET="secret-de-sesion-de-test",
)


def _app(**overrides) -> Settings:
    base = dict(BASIC_AUTH)
    base.update(overrides)
    return Settings(**base)


def _client(**overrides) -> TestClient:
    app = create_app(_app(**overrides))
    app.dependency_overrides[get_settings] = lambda: _app(**overrides)
    return TestClient(app, follow_redirects=False)


def _totp() -> str:
    return pyotp.TOTP(TOTP_SECRET).now()


# ---------------------------------------------------------------------------
# Comportamiento con credenciales de admin configuradas (producción real)
# ---------------------------------------------------------------------------
def test_raiz_sin_sesion_redirige_al_login():
    client = _client()

    resp = client.get("/")

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_dashboard_alias_sin_sesion_redirige_al_login():
    client = _client()

    resp = client.get("/dashboard")

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_v1_sin_sesion_y_sin_api_key_devuelve_401():
    client = _client()

    resp = client.get("/v1/monitoring/overview")

    assert resp.status_code == 401


def test_login_page_muestra_todos_los_campos():
    client = _client()

    resp = client.get("/login")

    assert resp.status_code == 200
    assert "Acceso restringido a administradores autorizados" in resp.text
    assert 'name="username"' in resp.text
    assert 'name="password"' in resp.text
    assert 'name="code"' in resp.text


def test_login_con_contrasena_incorrecta_devuelve_401():
    client = _client()

    resp = client.post(
        "/login",
        data={"username": "admin", "password": "mal", "code": _totp()},
    )

    assert resp.status_code == 401
    assert "incorrectos" in resp.text.lower()


def test_login_con_totp_incorrecto_devuelve_401():
    client = _client()

    resp = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "contraseña-super-segura-2026",
            "code": "000000",
        },
    )

    assert resp.status_code == 401
    assert "incorrectos" in resp.text.lower()


def test_login_correcto_crea_sesion_y_abre_dashboard_y_v1():
    client = _client()

    resp = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "contraseña-super-segura-2026",
            "code": _totp(),
        },
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    cookie = client.cookies.get("siem_session")
    assert cookie

    # Con la cookie de sesión, el dashboard real y /v1/* pasan.
    # /dashboard es un alias que devuelve 307 hacia "/" (siem/router/api.py).
    assert client.get("/").status_code == 200
    assert client.get("/dashboard").status_code == 307
    assert client.get("/v1/monitoring/overview").status_code == 200


def test_login_cookie_es_httponly():
    client = _client()

    resp = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "contraseña-super-segura-2026",
            "code": _totp(),
        },
    )

    set_cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "secure" not in set_cookie  # desarrollo; en producción sí
    assert "samesite=lax" in set_cookie


def test_login_cookie_secure_en_produccion():
    client = _client(ENVIRONMENT="production", SIAM_API_KEY="clave")

    resp = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "contraseña-super-segura-2026",
            "code": _totp(),
        },
    )

    assert "secure" in resp.headers["set-cookie"].lower()


def test_logout_borra_la_sesion():
    client = _client()
    client.post(
        "/login",
        data={
            "username": "admin",
            "password": "contraseña-super-segura-2026",
            "code": _totp(),
        },
    )
    assert client.get("/").status_code == 200

    resp = client.post("/logout")

    assert resp.status_code == 303
    assert client.get("/").status_code == 303  # vuelve a pedir login


def test_demo_sigue_publica_con_auth_activa():
    client = _client()

    # La demo apunta por defecto al siam_demo.db REAL (siem/router/demo.py) y
    # su seed escribe en él -- este test solo verifica que /demo/* sigue
    # pública con auth activa, sin depender de ese fichero (ni de sus
    # permisos), así que apuntamos get_demo_store a una base en memoria.
    demo_engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=demo_engine)
    demo_session = sessionmaker(bind=demo_engine)()

    def _override_demo_store():
        yield SiemStore(demo_session)

    client.app.dependency_overrides[get_demo_store] = _override_demo_store
    try:
        assert client.get("/demo").status_code == 200
        assert client.get("/demo/dashboard").status_code == 200
        assert client.get("/demo/v1/monitoring/overview").status_code == 200
    finally:
        client.app.dependency_overrides.pop(get_demo_store, None)
        demo_session.close()


def test_honeypot_sigue_publico_con_auth_activa():
    client = _client()

    assert client.get("/admin").status_code == 200


def test_health_y_login_publicos_con_auth_activa():
    client = _client()

    assert client.get("/health").status_code == 200
    assert client.get("/login").status_code == 200


# ---------------------------------------------------------------------------
# Sin credenciales de admin configuradas (desarrollo local puro)
# ---------------------------------------------------------------------------
def test_sin_auth_configurada_raiz_se_sirve_directamente():
    client = _client(SIAM_ADMIN_USERNAME=None, SIAM_ADMIN_TOTP_SECRET=None)

    assert client.get("/").status_code == 200


def test_configuracion_parcial_no_bloquea_el_dashboard():
    # Solo SIAM_ADMIN_USERNAME sin el resto de vars: el login no debería
    # activarse y el panel real no debe quedar encerrado detrás de un /login
    # que por definición no puede validar a nadie.
    client = _client(SIAM_ADMIN_PASSWORD_HASH=None, SIAM_ADMIN_TOTP_SECRET=None)

    assert client.get("/").status_code == 200
    assert client.get("/v1/monitoring/overview").status_code == 200


def test_sin_auth_configurada_v1_sigue_abierto():
    client = _client(SIAM_ADMIN_USERNAME=None, SIAM_ADMIN_TOTP_SECRET=None)

    assert client.get("/v1/monitoring/overview").status_code == 200


# ---------------------------------------------------------------------------
# /v1/* también acepta la API key compartida sin sesión (integraciones)
# ---------------------------------------------------------------------------
def test_v1_con_api_key_y_sin_sesion_accede():
    client = _client(SIAM_API_KEY="clave-integracion")

    resp = client.get(
        "/v1/monitoring/overview",
        headers={"X-SIAM-API-Key": "clave-integracion"},
    )

    assert resp.status_code == 200


def test_pagina_login_con_sesion_redirige_a_raiz():
    client = _client()
    client.post(
        "/login",
        data={
            "username": "admin",
            "password": "contraseña-super-segura-2026",
            "code": _totp(),
        },
    )

    resp = client.get("/login")

    assert resp.status_code == 303
    assert resp.headers["location"] == "/"