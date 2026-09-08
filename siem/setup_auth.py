"""Alta de credenciales del administrador del SOC real (usuario + 2FA TOTP).

Uso:
    .venv/bin/python -m siem.setup_auth

Te pide el nombre de usuario y la contraseña (no queda por escrito), genera:

  * SIAM_ADMIN_PASSWORD_HASH  -- hash scrypt (siem/auth.py::hash_password).
  * SIAM_ADMIN_TOTP_SECRET    -- secreto base32 para la app de autenticación.
  * SIAM_AUTH_SESSION_SECRET  -- secreto que firma la cookie de sesión.

e imprime el bloque de líneas .env listo para pegar en .env.production (o en
el .env si quieres login también en desarrollo local), más la URI otpauth
para añadir el TOTP a Google Authenticator / Aegis / 1Password.

La contraseña nunca se imprime: solo su hash. Vuelve a ejecutarlo siempre que
quiera regenerarse el secreto 2FA (p.ej. si se pierde el dispositivo).
"""
from __future__ import annotations

import getpass
import secrets

import pyotp

from siem.auth import hash_password


def main() -> None:
    print("=== Alta de administrador del SOC real (login + 2FA) ===\n")

    username = getpass.getpass("Nombre de usuario del administrador: ").strip() or "admin"
    while True:
        password = getpass.getpass("Contraseña del administrador: ")
        confirm = getpass.getpass("Repite la contraseña: ")
        if len(password) < 10:
            print("  La contraseña debe tener al menos 10 caracteres.\n")
        elif password != confirm:
            print("  Las contraseñas no coinciden.\n")
        else:
            break

    totp_secret = pyotp.random_base32()
    session_secret = secrets.token_urlsafe(32)

    print("""
===========================================================
1) Añade el 2FA a tu app de autenticación.

   URI otpauth (Google Authenticator / Aegis / 1Password):
""")
    uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SIAM Security")
    print(f"   {uri}\n")
    print(f"   Si prefieres entrada manual, el secreto es:\n   {totp_secret}\n")

    print("2) Pega este bloque en .env.production (despliegue real):\n")
    print("# Acceso al panel real (login + 2FA). Generado con python -m siem.setup_auth")
    print(f"SIAM_ADMIN_USERNAME={username}")
    print(f"SIAM_ADMIN_PASSWORD_HASH={hash_password(password)}")
    print(f"SIAM_ADMIN_TOTP_SECRET={totp_secret}")
    print(f"SIAM_AUTH_SESSION_SECRET={session_secret}")
    print("""
Verifícalo tras desplegar: abre siem.praxialabs.com y deberías ver la página
de acceso en vez del dashboard. La demo pública (/demo/dashboard) sigue sin
login a propósito.
""")


if __name__ == "__main__":
    main()