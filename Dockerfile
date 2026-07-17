FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Expose the port defined in .env (default 8001)
EXPOSE 8001

# Run the FastAPI app
#
# Corrección (2026-07-05, segunda vuelta): la v1 de este CMD combinaba
# --header + middleware -> duplicado (ver historial en CLAUDE.md). La v2
# quitó los --header y dejó solo --no-server-header confiando en que
# suprimiría el "Server: uvicorn" real -- pero José lo probó con curl -sD-
# contra un contenedor recién construido y el "server: uvicorn" seguía
# apareciendo IGUAL junto al falso, pese al flag. Es decir: --no-server-header
# por la CLI de uvicorn no está suprimiendo el header por defecto en este
# entorno/versión (uvicorn[standard]==0.30.5) -- no vale la pena seguir
# confiando en ese flag.
#
# Se cambia de raíz el mecanismo de arranque: en vez de `uvicorn
# siem.main:app` (CLI), se usa `python -m siem.main`, que SÍ ejecuta el
# bloque `if __name__ == "__main__":` de siem/main.py -- ahí
# server_header=False se pasa de forma programática a uvicorn.run(), el
# camino más estándar y probado de esta misma librería (a diferencia del
# flag de CLI, que aquí se ha demostrado que no funciona). El valor falso de
# Server/X-Powered-By lo sigue poniendo únicamente el middleware.
CMD ["python", "-m", "siem.main"]
