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

    # Base para construir los enlaces de tracking (clic/reporte/confirmación
    # de lectura) que se incrustan en el contenido de cada campaña.
    CAMPAIGN_BASE_URL: str = "http://localhost:8001"

    # Cada cuántos segundos el scheduler de campañas (siem/campaign_scheduler.py)
    # revisa si hay campañas con starts_at vencido para enviarlas solas.
    CAMPAIGN_SCHEDULER_INTERVAL_SECONDS: int = 30

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Se mantiene `settings` como instancia directa por compatibilidad con código
# existente que hacía `from siem.config import settings`.
settings = get_settings()
