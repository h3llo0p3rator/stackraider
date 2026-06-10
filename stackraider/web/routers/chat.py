import json
from typing import Optional

from fastapi import APIRouter, Cookie, WebSocket, WebSocketDisconnect

from stackraider.graphql import chat_service
from stackraider.web.config import settings
from stackraider.web.schemas.graphql import Finding, GeneratedQuery, ParsedSchema
from stackraider.web.session import get_or_create_session, resolve_session_id

router = APIRouter(prefix="/api", tags=["chat"])


def _code_scan_summary(state: dict) -> str:
    scan = state.get("scan_result")
    if not scan:
        return ""
    burp_n = len(state.get("burp_transactions") or [])
    return (
        f"\n## Code Scan Context\n"
        f"Target: {scan.get('target_path')}\n"
        f"Findings: {scan.get('total_findings', 0)}\n"
        f"Burp requests loaded: {burp_n}\n"
    )


@router.websocket("/chat")
async def chat_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            raw = await websocket.receive_text()
            payload = json.loads(raw)

            messages = payload.get("messages", [])
            model = payload.get("model") or settings.default_model
            host = payload.get("ollama_host") or settings.ollama_host

            schema = None
            if payload.get("schema"):
                schema = ParsedSchema.model_validate(payload["schema"])

            findings = None
            if payload.get("findings"):
                findings = [Finding.model_validate(f) for f in payload["findings"]]

            queries = None
            if payload.get("queries"):
                queries = [GeneratedQuery.model_validate(q) for q in payload["queries"]]

            session_id = payload.get("session_id")
            _, state = get_or_create_session(session_id)
            code_ctx = _code_scan_summary(state)

            await websocket.send_json({"type": "start"})

            async for token in chat_service.stream_chat(
                host=host,
                model=model,
                messages=messages,
                schema=schema,
                findings=findings,
                queries=queries,
                extra_system=code_ctx,
            ):
                await websocket.send_json({"type": "token", "content": token})

            await websocket.send_json({"type": "done"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "content": str(e)})
        except Exception:
            pass
