from __future__ import annotations

import html

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from siem.auth import SESSION_COOKIE, create_session, session_username, verify_password, verify_totp
from siem.config import Settings, get_settings

router = APIRouter(tags=["auth"])


def _page(error: str = "") -> str:
    """Página de acceso al panel real (solo admin, 2FA TOTP).

    Estilo inspirado en praxialabs.com/admin -- mismo mensaje de "Acceso
    restringido a administradores autorizados" -- pero con la estética dark
    del SOC de SIEM. Una sola página: usuario + contraseña + código 2FA.
    """
    message = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Acceso al SOC · SIEM Security</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
         display: grid; place-items: center; min-height: 100vh; margin: 0; padding: 16px; }}
  main {{ width: min(400px, 100%); background: #1e293b; border: 1px solid #334155;
         border-radius: 14px; padding: 32px; box-sizing: border-box; }}
  .brand {{ font: 700 13px/1.2 ui-monospace, monospace; letter-spacing: 0.12em;
           text-transform: uppercase; color: #60a5fa; margin: 0 0 18px; }}
  h1 {{ margin: 0 0 8px; font-size: 22px; }}
  .sub {{ color: #94a3b8; font-size: 14px; margin: 0 0 6px; }}
  .hint {{ color: #64748b; font-size: 13px; margin: 0 0 4px; }}
  label {{ display: block; color: #cbd5e1; font-size: 13px; margin: 16px 0 6px; }}
  input {{ width: 100%; box-sizing: border-box; background: #0f172a; border: 1px solid #475569;
          border-radius: 6px; color: #fff; padding: 10px; font-size: 15px; }}
  input:focus {{ outline: none; border-color: #2563eb; box-shadow: 0 0 0 2px #2563eb40; }}
  button {{ width: 100%; margin-top: 22px; padding: 11px; border: 0; border-radius: 6px;
           background: #2563eb; color: #fff; font: 600 15px system-ui, sans-serif;
           cursor: pointer; }}
  button:hover {{ background: #1d4ed8; }}
  .error {{ color: #fda4af; background: #4c0519; border: 1px solid #9f1239;
           padding: 10px; border-radius: 6px; margin: 16px 0 0; }}
  footer {{ margin-top: 24px; color: #64748b; font-size: 12px; text-align: center; }}
</style></head>
<body><main>
  <p class="brand">Praxia Labs · SIEM Security SOC</p>
  <h1>Acceso al panel</h1>
  <p class="sub">Acceso restringido a administradores autorizados.</p>
  <p class="hint">Introduce tus credenciales y el código 2FA de tu aplicación de autenticación.</p>
  {message}
  <form method="post" action="/login" autocomplete="on">
    <label for="username">Usuario</label>
    <input id="username" name="username" autocomplete="username" autofocus required>
    <label for="password">Contraseña</label>
    <input id="password" type="password" name="password" autocomplete="current-password" required>
    <label for="code">Código 2FA</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
           pattern="[0-9]{{6}}" maxlength="6" placeholder="000000" required>
    <button type="submit">Entrar</button>
  </form>
  <footer>SIEM Security · SOC virtual con IA · datos en reposo cifrados</footer>
</main></body></html>"""


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, settings: Settings = Depends(get_settings)) -> HTMLResponse:
    if session_username(request.cookies.get(SESSION_COOKIE), settings.SIAM_AUTH_SESSION_SECRET):
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(_page(), headers={"Cache-Control": "no-store"})


@router.post("/login", response_model=None)
def login(
    username: str = Form(""), password: str = Form(""), code: str = Form(""),
    settings: Settings = Depends(get_settings),
) -> HTMLResponse | RedirectResponse:
    configured = all((settings.SIAM_ADMIN_USERNAME, settings.SIAM_ADMIN_PASSWORD_HASH,
                      settings.SIAM_ADMIN_TOTP_SECRET, settings.SIAM_AUTH_SESSION_SECRET))
    valid = configured and username == settings.SIAM_ADMIN_USERNAME
    valid = valid and verify_password(password, settings.SIAM_ADMIN_PASSWORD_HASH)
    valid = valid and verify_totp(code, settings.SIAM_ADMIN_TOTP_SECRET)
    if not valid:
        return HTMLResponse(_page("Credenciales o código 2FA incorrectos."), status_code=401)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, create_session(username, settings.SIAM_AUTH_SESSION_SECRET),
                        httponly=True, secure=settings.ENVIRONMENT == "production",
                        samesite="lax", max_age=8 * 60 * 60, path="/")
    return response


@router.post("/logout")
def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response