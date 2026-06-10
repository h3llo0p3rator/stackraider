"""In-memory session store for StackRaider web UI."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

SESSION_COOKIE = "stackraider_session"
# Legacy cookie name (read during transition)
LEGACY_SESSION_COOKIE = "srcsniff_session"

_sessions: Dict[str, dict] = {}
_code_analyses: Dict[str, dict] = {}


def _empty_session() -> dict:
    return {
        "scan_result": None,
        "burp_transactions": [],
        "default_path": None,
        "burp_jar": None,
        "latest_code_analysis": None,
        "graphql_schema": None,
        "graphql_findings": [],
        "graphql_queries": [],
        "latest_graphql_analysis": None,
    }


def get_or_create_session(session_id: Optional[str] = None) -> tuple[str, dict]:
    if session_id and session_id in _sessions:
        return session_id, _sessions[session_id]
    sid = str(uuid.uuid4())
    _sessions[sid] = _empty_session()
    return sid, _sessions[sid]


def resolve_session_id(
    stackraider_session: Optional[str] = None,
    legacy_session: Optional[str] = None,
) -> Optional[str]:
    return stackraider_session or legacy_session


def log_entry(message: str) -> dict:
    return {
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "message": message,
    }


def context_log_message(context: dict) -> str:
    parts = [
        f"{context['findings_in_prompt']} findings",
        f"{len(context['source_files'])} source file(s)",
        f"{context['routes_in_prompt']} routes",
    ]
    if context["uses_burp"]:
        parts.append(
            f"{context['burp_loaded']} Burp requests loaded "
            f"({context['burp_in_prompt']} included in prompt)"
        )
    else:
        parts.append("no Burp traffic loaded")
    return "Built LLM context: " + ", ".join(parts)


def get_code_analyses() -> Dict[str, dict]:
    return _code_analyses
