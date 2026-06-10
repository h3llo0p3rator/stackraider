"""Shared Ollama client utilities."""

from __future__ import annotations

from typing import AsyncIterator, Generator, List

from stackraider.web.config import settings

try:
    import ollama
except ImportError:
    ollama = None  # type: ignore

DEFAULT_OLLAMA_HOST = settings.ollama_host


def ollama_reachable(host: str | None = None) -> bool:
    host = host or DEFAULT_OLLAMA_HOST
    if ollama is None:
        return False
    try:
        client = ollama.Client(host=host)
        client.list()
        return True
    except Exception:
        return False


def list_models(host: str | None = None) -> List[dict]:
    host = host or DEFAULT_OLLAMA_HOST
    if ollama is None:
        return []
    try:
        client = ollama.Client(host=host)
        resp = client.list()
        models = resp.get("models", [])
        return [
            {
                "name": m.get("name", m.get("model", "")),
                "size": m.get("size", 0),
                "family": (m.get("details") or {}).get("family", ""),
                "parameter_size": (m.get("details") or {}).get("parameter_size", ""),
            }
            for m in models
        ]
    except Exception:
        return []


def stream_chat(
    model: str,
    prompt: str,
    host: str | None = None,
) -> Generator[str, None, None]:
    host = host or DEFAULT_OLLAMA_HOST
    if ollama is None:
        yield "Error: ollama package not installed. Run: pip install ollama"
        return
    client = ollama.Client(host=host)
    try:
        stream = client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            stream=True,
        )
        for chunk in stream:
            content = chunk.get("message", {}).get("content", "")
            if content:
                yield content
    except Exception as e:
        yield f"\n\n**Error:** {e}"


async def async_stream_chat(
    model: str,
    prompt: str,
    host: str | None = None,
) -> AsyncIterator[str]:
    host = host or DEFAULT_OLLAMA_HOST
    if ollama is None:
        yield "Error: ollama package not installed. Run: pip install ollama"
        return
    try:
        from ollama import AsyncClient

        client = AsyncClient(host=host)
        stream = await client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            stream=True,
        )
        async for chunk in stream:
            content = chunk.get("message", {}).get("content", "")
            if content:
                yield content
    except Exception as e:
        yield f"\n\n**Error:** {e}"
