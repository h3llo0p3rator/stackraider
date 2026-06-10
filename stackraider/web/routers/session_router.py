"""Unified session and export routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Cookie, Response

from stackraider.web.burp_parser import _find_burp_jar, summarize_traffic
from stackraider.web.correlation import correlate_findings
from stackraider.web.session import (
    LEGACY_SESSION_COOKIE,
    SESSION_COOKIE,
    get_or_create_session,
    resolve_session_id,
)
from pathlib import Path

router = APIRouter(prefix="/api", tags=["session"])


@router.get("/session")
async def get_session(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    sid, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    files_with_findings = []
    if state.get("scan_result"):
        files_with_findings = sorted({
            f["file_path"] for f in state["scan_result"].get("findings", [])
        })
    jar = state.get("burp_jar") or _find_burp_jar()
    burp_summary = summarize_traffic(state.get("burp_transactions", []))
    latest_code = state.get("latest_code_analysis")
    gql_findings = state.get("graphql_findings") or []
    return {
        "session_id": sid,
        "has_scan": state.get("scan_result") is not None,
        "scan_findings": state.get("scan_result", {}).get("total_findings", 0) if state.get("scan_result") else 0,
        "has_burp": bool(state.get("burp_transactions")),
        "burp_summary": burp_summary if state.get("burp_transactions") else None,
        "has_graphql": bool(state.get("graphql_schema")),
        "graphql_findings_count": len(gql_findings),
        "has_analysis": bool(latest_code and latest_code.get("full_text")),
        "default_path": state.get("default_path"),
        "files_with_findings": files_with_findings,
        "burp_jar": jar,
        "burp_jar_valid": bool(jar and Path(jar).is_file()),
        "correlations": correlate_findings(state),
    }


@router.get("/export")
async def export_session(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    _, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    return {
        "code_scan": state.get("scan_result"),
        "burp_summary": summarize_traffic(state.get("burp_transactions", [])),
        "burp_transactions": state.get("burp_transactions") and len(state.get("burp_transactions", [])),
        "graphql_schema": state.get("graphql_schema"),
        "graphql_findings": state.get("graphql_findings", []),
        "graphql_queries": state.get("graphql_queries", []),
        "code_analysis": state.get("latest_code_analysis"),
        "graphql_analysis": state.get("latest_graphql_analysis"),
        "correlations": correlate_findings(state),
    }
