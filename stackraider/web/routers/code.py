"""Code scan, Burp import, and code LLM analysis routes."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Cookie, File, HTTPException, Response, UploadFile
from fastapi.responses import StreamingResponse

from stackraider.core.scanner import SecurityScanner
from stackraider.web.burp_parser import (
    _find_burp_jar,
    match_traffic_to_routes,
    parse_burp_upload,
    summarize_traffic,
    validate_burp_jar,
)
from stackraider.web.correlation import build_graphql_context_for_code_prompt
from stackraider.web.helpers import burp_to_dict, scan_result_to_dict
from stackraider.web.llm.code import (
    build_analysis_context,
    build_analysis_prompt,
    parse_attack_paths_from_markdown,
)
from stackraider.web.llm.shared import async_stream_chat, ollama_reachable
from stackraider.web.schemas.code import BurpConfigRequest, CodeAnalyzeRequest, ScanRequest
from stackraider.web.session import (
    LEGACY_SESSION_COOKIE,
    SESSION_COOKIE,
    context_log_message,
    get_code_analyses,
    get_or_create_session,
    log_entry,
    resolve_session_id,
)

router = APIRouter(prefix="/api/code", tags=["code"])


def _set_session_cookie(response: Response, sid: str) -> None:
    response.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="lax")


@router.get("/browse")
async def browse_directory(
    path: Optional[str] = None,
    mode: str = "dirs",
    ext: Optional[str] = None,
):
    if path:
        current = Path(path).expanduser()
        try:
            current = current.resolve()
        except (OSError, RuntimeError):
            raise HTTPException(400, f"Invalid path: {path}")
    else:
        current = Path.home()

    if not current.exists():
        raise HTTPException(404, f"Path does not exist: {current}")
    if not current.is_dir():
        current = current.parent

    entries: List[dict] = []
    try:
        children = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except PermissionError:
        raise HTTPException(403, f"Permission denied: {current}")

    for item in children:
        if item.name.startswith("."):
            continue
        try:
            is_dir = item.is_dir()
            if not is_dir and mode != "files":
                continue
            if not is_dir and ext and not item.name.lower().endswith(ext.lower()):
                continue
            entries.append({
                "name": item.name,
                "path": str(item.resolve()),
                "is_dir": is_dir,
            })
        except (OSError, PermissionError):
            continue

    parent = str(current.parent) if current.parent != current else None
    return {"current": str(current), "parent": parent, "entries": entries[:500]}


@router.post("/scan")
async def run_scan(
    body: ScanRequest,
    response: Response,
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    target = Path(body.path).expanduser().resolve()
    if not target.exists():
        raise HTTPException(400, f"Path does not exist: {body.path}")

    sid, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    _set_session_cookie(response, sid)

    config = {
        "min_severity": body.severity,
        "exclude_rules": body.exclude_rules.split(",") if body.exclude_rules else [],
        "unminify": body.unminify,
        "include_vendor": body.include_vendor,
        "quiet": True,
    }
    scanner = SecurityScanner(str(target), config)
    result = scanner.scan(max_workers=body.workers)
    data = scan_result_to_dict(result)
    state["scan_result"] = data
    state["default_path"] = str(target)

    if state.get("burp_transactions") and data.get("routes"):
        txns, route_map = match_traffic_to_routes(state["burp_transactions"], data["routes"])
        state["burp_transactions"] = txns
        data["burp_route_matches"] = route_map

    return data


@router.get("/scan/result")
async def get_scan_result(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    _, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    if not state.get("scan_result"):
        raise HTTPException(404, "No scan result. Run a scan first.")
    return state["scan_result"]


@router.get("/burp/config")
async def get_burp_config(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    _, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    jar = state.get("burp_jar") or _find_burp_jar()
    return {"burp_jar": jar, "valid": bool(jar and Path(jar).is_file())}


@router.post("/burp/config")
async def set_burp_config(
    body: BurpConfigRequest,
    response: Response,
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    sid, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    _set_session_cookie(response, sid)
    try:
        jar = validate_burp_jar(body.burp_jar)
    except ValueError as e:
        raise HTTPException(400, str(e))
    state["burp_jar"] = jar
    return {"burp_jar": jar, "valid": True}


@router.post("/burp/upload")
async def upload_burp(
    response: Response,
    file: UploadFile = File(...),
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    sid, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    _set_session_cookie(response, sid)

    content = await file.read()
    filename = file.filename or "upload"
    try:
        transactions = parse_burp_upload(content, filename, burp_jar=state.get("burp_jar"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(400, f"Failed to parse Burp export: {e}")

    route_map = {}
    if state.get("scan_result") and state["scan_result"].get("routes"):
        transactions, route_map = match_traffic_to_routes(
            transactions, state["scan_result"]["routes"]
        )

    state["burp_transactions"] = transactions
    return {
        "summary": summarize_traffic(transactions),
        "transactions": burp_to_dict(transactions),
        "route_matches": route_map if state.get("scan_result") else {},
    }


@router.get("/burp/traffic")
async def get_burp_traffic(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    _, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    transactions = state.get("burp_transactions", [])
    return {
        "summary": summarize_traffic(transactions),
        "transactions": burp_to_dict(transactions),
    }


@router.post("/analyze")
async def start_analysis(
    body: CodeAnalyzeRequest,
    response: Response,
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    sid, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    _set_session_cookie(response, sid)

    if not state.get("scan_result"):
        raise HTTPException(400, "Run a scan before analysis.")
    if not ollama_reachable(body.ollama_host):
        raise HTTPException(503, "Ollama is not reachable.")

    file_path = body.file_path if body.scope != "all" else None
    burp_txns = state.get("burp_transactions")
    gql_ctx = build_graphql_context_for_code_prompt(state)

    prompt = build_analysis_prompt(
        state["scan_result"],
        file_path=file_path,
        burp_transactions=burp_txns,
        graphql_context=gql_ctx,
    )
    context = build_analysis_context(
        state["scan_result"],
        file_path=file_path,
        burp_transactions=burp_txns,
        prompt=prompt,
    )
    log = [
        log_entry(context_log_message(context)),
        log_entry(f"Prompt size: {len(prompt):,} characters"),
        log_entry(f"Starting Ollama stream with model {body.model}"),
    ]
    if gql_ctx:
        log.append(log_entry("GraphQL schema findings included in prompt"))

    analysis_id = str(uuid.uuid4())
    analyses = get_code_analyses()
    analyses[analysis_id] = {
        "model": body.model,
        "prompt": prompt,
        "host": body.ollama_host,
        "file_path": file_path,
        "scope": body.scope,
        "session_id": sid,
        "context": context,
        "log": log,
        "full_text": "",
        "done": False,
    }
    state["latest_code_analysis"] = {
        "analysis_id": analysis_id,
        "model": body.model,
        "scope": body.scope,
        "file_path": file_path,
        "context": context,
        "log": list(log),
        "full_text": "",
        "done": False,
        "attack_paths": [],
    }
    return {"analysis_id": analysis_id, "file_path": file_path, "context": context, "log": log}


@router.get("/analyze/stream/{analysis_id}")
async def stream_analysis(analysis_id: str):
    analyses = get_code_analyses()
    if analysis_id not in analyses:
        raise HTTPException(404, "Analysis not found.")
    analysis = analyses[analysis_id]

    def _sync_session() -> None:
        from stackraider.web.session import _sessions

        sid = analysis.get("session_id")
        if not sid or sid not in _sessions:
            return
        st = _sessions[sid]
        if st.get("latest_code_analysis", {}).get("analysis_id") != analysis_id:
            return
        st["latest_code_analysis"].update({
            "full_text": analysis["full_text"],
            "done": analysis["done"],
            "log": analysis.get("log", []),
            "attack_paths": parse_attack_paths_from_markdown(analysis["full_text"]),
        })

    async def event_generator():
        try:
            async for token in async_stream_chat(
                analysis["model"], analysis["prompt"], analysis["host"]
            ):
                analysis["full_text"] += token
                yield f"data: {json.dumps({'token': token, 'done': False})}\n\n"
                await asyncio.sleep(0)
            analysis["done"] = True
            paths = parse_attack_paths_from_markdown(analysis["full_text"])
            analysis["log"].append(
                log_entry(
                    f"Analysis complete ({len(analysis['full_text']):,} characters, "
                    f"{len(paths)} attack path section(s))"
                )
            )
            _sync_session()
            yield f"data: {json.dumps({'token': '', 'done': True, 'full_text': analysis['full_text'], 'attack_paths': paths, 'log': analysis.get('log', [])})}\n\n"
        except Exception as e:
            analysis["log"].append(log_entry(f"Error: {e}"))
            _sync_session()
            yield f"data: {json.dumps({'error': str(e), 'done': True, 'log': analysis.get('log', [])})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.get("/analyze/{analysis_id}")
async def get_analysis(analysis_id: str):
    analyses = get_code_analyses()
    if analysis_id not in analyses:
        raise HTTPException(404, "Analysis not found.")
    a = analyses[analysis_id]
    return {
        "analysis_id": analysis_id,
        "done": a["done"],
        "full_text": a["full_text"],
        "attack_paths": parse_attack_paths_from_markdown(a["full_text"]),
        "file_path": a.get("file_path"),
        "scope": a.get("scope"),
        "model": a.get("model"),
        "context": a.get("context"),
        "log": a.get("log", []),
    }


@router.get("/analyze/latest")
async def get_latest_analysis(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    _, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    latest = state.get("latest_code_analysis")
    if not latest:
        raise HTTPException(404, "No analysis in this session yet.")
    return latest
