"""StackRaider unified configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ollama_host: str = "http://localhost:11434"
    default_model: str = "llama3.2"
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ]

    model_config = SettingsConfigDict(
        env_prefix="STACKRAIDER_",
        env_file=".env",
        extra="ignore",
    )


settings = Settings()

# Backward compatibility
DEFAULT_OLLAMA_HOST = settings.ollama_host
