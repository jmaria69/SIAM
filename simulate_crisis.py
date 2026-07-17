import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()  # lee .env cuando este script se ejecuta suelto (no vía FastAPI)

# CONFIGURACIÓN DE ENDPOINTS LOCALES (SIEM)
URL_BASE = "http://localhost:8001"
URL_INGEST = f"{URL_BASE}/v1/ingest/jira"
URL_METRICS = f"{URL_BASE}/v1/metrics"

# CONFIGURACIÓN DE TELEGRAM — antes hardcodeada aquí en texto plano y
# commiteada al repo (credencial expuesta). Ahora se lee de .env.
# IMPORTANTE: el token que estaba escrito antes en este archivo quedó
# expuesto en el historial de git. Hay que revocarlo en BotFather y generar
# uno nuevo; esto no se puede hacer automáticamente desde aquí.
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

def enviar_telegram(mensaje):
    """Envía notificaciones push reales a Telegram si las credenciales existen."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[TELEGRAM] TELEGRAM_TOKEN/TELEGRAM_CHAT_ID no configurados en .env — se omite el envío.")
        return
    
    # URL CANÓNICA CORRECTA DE LA API DE TELEGRAM
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    
    payload = {
        "chat_id": TELEGRAM_CHAT_ID, 
        "text": mensaje, 
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code != 200:
            print(f"[TELEGRAM ERROR] Código de estado: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[TELEGRAM ERROR] No se pudo conectar con Telegram: {e}")
       

print("=== INICIANDO SECUENCIA PARA GRABACIÓN DE VIDEO DEMO ===")
print("[Escena 1] Simulando actividad normal... Todo en orden.")
time.sleep(3)

# -------------------------------------------------------------------------
# ESCENA 2: IMPACTO Y GENERACIÓN DE TICKET CRÍTICO
# -------------------------------------------------------------------------
print("\n🚨 ¡ALERTA! Provocando Error 502 (Bad Gateway) simulado en la infraestructura...")

msg_alerta = (
    "🚨 **[ALERTA DE INFRAESTRUCTURA]**\n"
    "Servicio: API Gateway (jmr-platform)\n"
    "Estado: Caído (Error 502 / Bad Gateway)\n"
    "Entorno: WSL2 (Ubuntu-22.04)\n"
    "🤖 OLGA está analizando los logs del sistema automáticamente..."
)
print(msg_alerta)
enviar_telegram(msg_alerta)

# Inyección real en el Backend para encender los KPIs en el Dashboard
payload_critico = {
    "ticket_id": "SIEM-502",
    "status": "critical",
    "service": "API Gateway",
    "description": "Error 502 Bad Gateway"
}

try:
    res = requests.post(URL_INGEST, json=payload_critico, timeout=5)
    if res.status_code == 200:
        print("[SIEM SYSTEM] Ticket crítico inyectado con éxito en el Backend.")
except Exception as e:
    print(f"[SIEM ERROR] Fallo de conexión al inyectar: {e}")

print("\n⏳ Manteniendo estado crítico durante 6 segundos para actualización del Dashboard...")
time.sleep(6)  # Da margen de sobra para que el bucle de 2s del frontend pinte el ticket

# -------------------------------------------------------------------------
# ESCENA 3: AUTO-RECUPERACIÓN POR OLGA
# -------------------------------------------------------------------------
print("\n🤖 [OLGA BOT - TELEGRAM]")
print("🔄 [DIAGNÓSTICO COMPLETADO]: El pool de conexiones de la Base de Datos local se ha agotado por pico de tráfico.")
print("🛠️ Acción Correctora: Ejecutando autorrecuperación: 'docker-compose restart backend'")

# Espera visual del progreso de recuperación
for i in range(1, 6):
    print(f"🔄 Progreso: [ {'#' * i}{'.' * (5-i)} ] {i*20}%")
    time.sleep(1)

# Simular la restauración del sistema en el backend modificando las métricas a 0 tickets activos
payload_recuperado = {
    "ticket_id": "SIEM-502",
    "status": "resolved",
    "service": "API Gateway",
    "description": "Sistema restaurado por OLGA"
}
try:
    requests.post(URL_INGEST, json=payload_recuperado, timeout=5)
except:
    pass

msg_recuperado = (
    "✅ **[SISTEMA RECUPERADO]**\n"
    "Resultado: API Gateway respondiendo correctamente (HTTP 200).\n"
    "Tiempo de respuesta de autorrecuperación: 14.2 segundos.\n"
    "🟢 El Dashboard de praxialabs.com ha vuelto a estado VERDE estable."
)
print(f"\n{msg_recuperado}")
enviar_telegram(msg_recuperado)

print("\n=== SECUENCIA FINALIZADA CON ÉXITO ===")
