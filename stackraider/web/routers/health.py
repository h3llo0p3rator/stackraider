from fastapi import APIRouter

from stackraider.graphql import model_manager
from stackraider.web.config import settings

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
async def health():
    status = await model_manager.check_ollama(settings.ollama_host)
    models = []
    if status.get("connected"):
        try:
            models = await model_manager.list_models(settings.ollama_host)
        except Exception:
            pass
    return {
        "status": "ok",
        "name": "StackRaider",
        **status,
        "default_model": settings.default_model,
        "model_count": len(models),
    }
