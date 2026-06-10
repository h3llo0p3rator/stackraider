import json
from typing import AsyncIterator

import httpx
from ollama import AsyncClient

from stackraider.web.schemas.graphql import ModelInfo, RecommendedModel

RECOMMENDED_MODELS = [
    RecommendedModel(
        name="llama3.2",
        description="General-purpose model, good balance of speed and quality for security analysis.",
        size_hint="~2GB",
    ),
    RecommendedModel(
        name="codellama",
        description="Strong at generating exploit queries and code snippets.",
        size_hint="~4GB",
    ),
    RecommendedModel(
        name="mistral",
        description="Fast reasoning for vulnerability assessment.",
        size_hint="~4GB",
    ),
    RecommendedModel(
        name="qwen2.5-coder",
        description="Excellent for GraphQL query generation and scripting.",
        size_hint="~5GB",
    ),
    RecommendedModel(
        name="deepseek-r1",
        description="Advanced reasoning for chaining attack paths.",
        size_hint="~8GB",
    ),
]


async def check_ollama(host: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{host}/api/tags")
            r.raise_for_status()
            return {"connected": True, "host": host}
    except Exception as e:
        return {"connected": False, "host": host, "error": str(e)}


async def list_models(host: str) -> list[ModelInfo]:
    client = AsyncClient(host=host)
    response = await client.list()
    models = []
    for m in response.models:
        details = m.details or {}
        models.append(
            ModelInfo(
                name=m.model,
                size=m.size,
                parameter_size=getattr(details, "parameter_size", None)
                if hasattr(details, "parameter_size")
                else details.get("parameter_size") if isinstance(details, dict) else None,
                quantization=getattr(details, "quantization_level", None)
                if hasattr(details, "quantization_level")
                else details.get("quantization_level") if isinstance(details, dict) else None,
                family=getattr(details, "family", None)
                if hasattr(details, "family")
                else details.get("family") if isinstance(details, dict) else None,
                modified_at=str(m.modified_at) if m.modified_at else None,
            )
        )
    return models


def get_recommended_models() -> list[RecommendedModel]:
    return RECOMMENDED_MODELS


async def pull_model(host: str, name: str) -> AsyncIterator[dict]:
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream(
            "POST",
            f"{host}/api/pull",
            json={"name": name, "stream": True},
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.strip():
                    continue
                data = json.loads(line)
                total = data.get("total")
                completed = data.get("completed")
                percent = None
                if total and completed:
                    percent = round(completed / total * 100, 1)
                yield {
                    "status": data.get("status", ""),
                    "digest": data.get("digest"),
                    "total": total,
                    "completed": completed,
                    "percent": percent,
                }


async def delete_model(host: str, name: str) -> bool:
    client = AsyncClient(host=host)
    await client.delete(name)
    return True
