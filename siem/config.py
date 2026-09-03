"""Configuración central de SIEM Security.

Usa pydantic-settings para cargar valores desde variables de entorno / .env,
tal y como ya establecía CLAUDE.md para APP_HOST y APP_PORT. Se amplía aquí
para cubrir el motor de IA plegable y las notificaciones, que antes vivían
hardcodeadas en simulate_crisis.py.
"""
from functools import lru_cache
from typing import Literal, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Servidor
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8001
    APP_NAME: str = "SIEM Security SOC"

    # Entorno de despliegue. "development" (default) deja /docs, /redoc y
    # /openapi.json activos como siempre. En "production" (siem/main.py,
    # create_app()) esas tres rutas se desactivan por completo -- Swagger UI
    # revela de inmediato que esto es FastAPI/Python, sin importar lo que
    # digan los headers Server/X-Powered-By de la mascarada de abajo. Hay que
    # poner ENVIRONMENT=production explícitamente en el .env real del
    # servidor desplegado; el default se queda en "development" a propósito
    # para no romper el flujo local de nadie sin querer.
    ENVIRONMENT: Literal["development", "production"] = "development"

    # CORS — en producción esto debe restringirse a los dominios reales del cliente
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:8000,http://localhost:8001"

    # Clave compartida que protege todo /v1/* (ver api_key_middleware en
    # main.py). Sin ella, cualquiera que alcance el backend -- por el túnel,
    # por la red local o por un futuro fallo de exposición de puerto como el
    # de 2026-09-03 -- tenía acceso completo sin login: incidentes, datos de
    # cliente PYME, y podía hacer que /v1/ai/chat y /v1/campaigns gastaran
    # las claves de Anthropic/OpenAI/SMTP del backend. None en desarrollo no
    # exige la cabecera (para no romper el flujo local); en producción es
    # obligatoria -- create_app() aborta el arranque si falta.
    SIAM_API_KEY: Optional[str] = None

    # Motor de IA plegable: anthropic | openai | local | none
    AI_PROVIDER: Literal["anthropic", "openai", "local", "none"] = "none"
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-4-5"
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"
    LOCAL_LLM_URL: Optional[str] = None  # p.ej. http://localhost:11434/v1 (Ollama, compatible OpenAI)
    LOCAL_LLM_MODEL: str = "llama3.1"

    # Notificaciones (Telegram) — antes hardcodeado en simulate_crisis.py, ahora en .env
    TELEGRAM_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None

    # Correlación de eventos
    CORRELATION_WINDOW_MINUTES: int = 15

    # SMTP para campañas de concienciación (email de phishing simulado,
    # comunicados, quizzes). Si no está configurado, siem/notifications.py
    # registra y omite el envío en vez de fallar — mismo criterio que
    # Telegram: una integración opcional nunca debe tumbar un endpoint.
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: Optional[str] = None
    SMTP_USE_TLS: bool = True

    # Alerta por email cuando se crea un incidente nuevo (ataque detectado).
    # Reutiliza el mismo SMTP de arriba -- es otro tipo de correo, no otro
    # servidor. Sin ALERT_EMAIL_TO no se envía nada (mismo criterio: una
    # integración opcional nunca debe tumbar la ingesta/correlación de
    # eventos). ALERT_EMAIL_MIN_SEVERITY filtra ruido de incidentes leves.
    ALERT_EMAIL_TO: Optional[str] = None
    ALERT_EMAIL_MIN_SEVERITY: Literal["info", "baja", "media", "alta", "critica"] = "media"

    # Base para construir los enlaces de tracking (clic/reporte/confirmación
    # de lectura) que se incrustan en el contenido de cada campaña.
    CAMPAIGN_BASE_URL: str = "http://localhost:8001"

    # Cada cuántos segundos el scheduler de campañas (siem/campaign_scheduler.py)
    # revisa si hay campañas con starts_at vencido para enviarlas solas.
    CAMPAIGN_SCHEDULER_INTERVAL_SECONDS: int = 30

    # WAAP híbrido -- capa cloud (Cloudflare).
    # Si CLOUDFLARE_API_TOKEN o CLOUDFLARE_ZONE_ID están vacíos, el pull no
    # arranca y no se traga excepciones en silencio -- el resto de SIAM
    # sigue funcionando igual (misma filosofía que SMTP/Telegram: una
    # integración opcional nunca debe tumbar el arranque).
    CLOUDFLARE_API_TOKEN: Optional[str] = None
    CLOUDFLARE_ZONE_ID: Optional[str] = None
    CLOUDFLARE_PULL_INTERVAL_SECONDS: int = 300  # 5 min: cabe en el plan Free
    # Cuántos minutos hacia atrás mirar en cada tick. Debe ser >= al intervalo
    # de pull para no perder eventos si un tick se retrasa. 10 min con pull
    # de 5 min da margen holgado y cursor-free (deduplicación por rayId).
    CLOUDFLARE_LOOKBACK_MINUTES: int = 10

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Se mantiene `settings` como instancia directa por compatibilidad con código
# existente que hacía `from siem.config import settings`.
settings = get_settings()
