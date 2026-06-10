"""Ollama LLM integration for vulnerability analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from stackraider.web.burp_parser import BurpTransaction, match_traffic_to_routes

from stackraider.web.llm.shared import (
    DEFAULT_OLLAMA_HOST,
    async_stream_chat,
    list_models,
    ollama_reachable,
    stream_chat,
)

MAX_SOURCE_CHARS = 12000
MAX_TRAFFIC_ITEMS = 12
MAX_TRAFFIC_BODY_CHARS = 800


def _format_finding(f: dict) -> str:
    lines = [
        f"### [{f.get('severity')}] {f.get('rule_id')} — {f.get('rule_name')}",
        f"File: {f.get('file_path')}:{f.get('line_number')}",
        f"Category: {f.get('category')} | CWE: {f.get('cwe_id', 'n/a')}",
        f"Line: {f.get('line_content', '')[:200]}",
    ]
    if f.get("description"):
        lines.append(f"Description: {f.get('description')[:300]}")
    if f.get("route_path"):
        lines.append(f"Linked route: {f.get('route_method', 'ALL')} {f.get('route_path')}")
    if f.get("param_name"):
        lines.append(f"Input param: {f.get('param_name')} (source: {f.get('param_source') or 'unknown'})")
    if f.get("enclosing_function"):
        lines.append(f"Enclosing function: {f.get('enclosing_function')}()")
    if f.get("exploitation"):
        lines.append(f"Scanner exploitation hint: {f.get('exploitation')[:400]}")
    ctx = f.get("context_before", []) + [f.get("line_content", "")] + f.get("context_after", [])
    if ctx:
        lines.append("Surrounding code:")
        for line in ctx[-8:]:
            lines.append(f"  {line[:160]}")
    return "\n".join(lines)


def _traffic_query(url: str, path: str) -> str:
    combined = url or path or ""
    if "?" in combined:
        return combined.split("?", 1)[1][:200]
    return ""


def _format_traffic(transactions: List[BurpTransaction]) -> str:
    if not transactions:
        return (
            "No Burp requests were selected for this scope. "
            "If traffic was loaded, it may not match discovered routes — "
            "still check whether API/HTML requests in the full export relate to the source files."
        )
    parts = []
    for i, t in enumerate(transactions[:MAX_TRAFFIC_ITEMS], 1):
        req_hdr = ", ".join(
            f"{k}: {v[:80]}"
            for k, v in list(t.request_headers.items())[:6]
        )
        resp_hdr = ", ".join(
            f"{k}: {v[:80]}"
            for k, v in list(t.response_headers.items())[:4]
        )
        parts.append(
            f"### Burp request #{i}: {t.method} {t.url}\n"
            f"Status: {t.status} | Host: {t.host} | Path: {t.path}\n"
            f"Query string: {_traffic_query(t.url, t.path) or '(none)'}\n"
            f"Matched static route: {t.matched_route_path or 'none — may be SPA asset, API, or unmapped'}\n"
            f"Request headers: {req_hdr or '(none)'}\n"
            f"Request body:\n{t.request_body[:MAX_TRAFFIC_BODY_CHARS]}\n"
            f"Response headers: {resp_hdr or '(none)'}\n"
            f"Response body:\n{t.response_body[:MAX_TRAFFIC_BODY_CHARS]}\n"
        )
    if len(transactions) > MAX_TRAFFIC_ITEMS:
        parts.append(f"... ({len(transactions) - MAX_TRAFFIC_ITEMS} more requests loaded but omitted from prompt)")
    return "\n".join(parts)


def _select_traffic_for_analysis(
    transactions: List[BurpTransaction],
    routes: List[dict],
    findings: List[dict],
    file_path: Optional[str] = None,
) -> List[BurpTransaction]:
    """Pick the Burp requests most likely to corroborate findings in scope."""
    if not transactions:
        return []

    scored: List[tuple] = []
    scope_routes = {r.get("path") for r in routes}
    if file_path:
        file_routes = {r.get("path") for r in routes if r.get("source_file") == file_path}
        if file_routes:
            scope_routes = file_routes

    finding_routes = {f.get("route_path") for f in findings if f.get("route_path")}
    finding_params = {f.get("param_name") for f in findings if f.get("param_name")}
    finding_snippets = [
        f.get("line_content", "").strip()[:60]
        for f in findings
        if len((f.get("line_content") or "").strip()) > 12
    ]

    for t in transactions:
        score = 0
        haystack = f"{t.url} {t.path} {t.request_body} {t.response_body}".lower()

        if t.matched_route_path and t.matched_route_path in scope_routes:
            score += 10
        if t.matched_route_path and t.matched_route_path in finding_routes:
            score += 8
        if file_path and t.matched_route_path:
            route_files = {
                r.get("source_file") for r in routes
                if r.get("path") == t.matched_route_path
            }
            if file_path in route_files:
                score += 6
        for param in finding_params:
            if param and param.lower() in haystack:
                score += 5
        for snippet in finding_snippets:
            if snippet.lower() in haystack:
                score += 4
        if file_path and file_path.split("/")[-1].lower() in haystack:
            score += 2
        if t.status and t.status.startswith(("4", "5")):
            score += 1

        scored.append((score, t))

    scored.sort(key=lambda x: x[0], reverse=True)
    selected = [t for s, t in scored if s > 0][:MAX_TRAFFIC_ITEMS]
    if not selected:
        selected = [t for _, t in scored[:MAX_TRAFFIC_ITEMS]]
    return selected


def _build_correlation_hints(
    findings: List[dict],
    transactions: List[BurpTransaction],
    routes: List[dict],
) -> str:
    """Pre-link findings to Burp requests so the model starts from concrete pairs."""
    route_handlers = {
        r.get("path"): r.get("source_file")
        for r in routes
        if r.get("path")
    }
    lines: List[str] = []

    for f in findings[:20]:
        rule = f.get("rule_id", "?")
        fp = f.get("file_path", "")
        ln = f.get("line_number", "?")
        route = f.get("route_path", "")
        param = f.get("param_name", "")
        snippet = (f.get("line_content") or "").strip()[:50]

        related: List[str] = []
        for i, t in enumerate(transactions, 1):
            haystack = f"{t.url} {t.path} {t.request_body} {t.response_body}"
            if route and t.matched_route_path == route:
                related.append(f"#{i} {t.method} {t.url} (status {t.status})")
            elif param and param in haystack:
                related.append(f"#{i} {t.method} {t.url} — param '{param}' in request/URL")
            elif snippet and len(snippet) > 12 and snippet in haystack:
                related.append(f"#{i} {t.method} {t.url} — code snippet appears in traffic")

        header = f"**{rule}** {fp}:{ln}"
        if related:
            lines.append(f"- {header} → Burp: {'; '.join(related[:3])}")
        elif route:
            handler = route_handlers.get(route, "unknown handler")
            lines.append(
                f"- {header} → route {route} (handler: {handler}) — "
                "NO matching Burp request; explain how to capture it"
            )
        else:
            lines.append(
                f"- {header} → no static route linked; search Burp for HTML/JS/API "
                f"requests that load or call `{fp}`"
            )

    return "\n".join(lines) if lines else "No findings in scope to correlate."


def _read_source(file_path: str, max_chars: int = MAX_SOURCE_CHARS) -> str:
    try:
        text = Path(file_path).read_text(encoding="utf-8", errors="replace")
        if len(text) > max_chars:
            return text[:max_chars] + f"\n\n... [truncated, {len(text) - max_chars} chars omitted]"
        return text
    except Exception as e:
        return f"[Could not read source: {e}]"


def _collect_analysis_scope(
    scan_result: dict,
    file_path: Optional[str] = None,
    burp_transactions: Optional[List[BurpTransaction]] = None,
) -> tuple:
    """Filter findings, routes, and Burp traffic for the selected analysis scope."""
    findings = scan_result.get("findings", [])
    routes = scan_result.get("routes", [])

    if file_path:
        findings = [f for f in findings if f.get("file_path") == file_path]
    files = sorted({f.get("file_path", "") for f in findings if f.get("file_path")})

    matched_traffic: List[BurpTransaction] = []
    if burp_transactions:
        if routes:
            updated, _ = match_traffic_to_routes(burp_transactions, routes)
        else:
            updated = list(burp_transactions)
        matched_traffic = _select_traffic_for_analysis(
            updated, routes, findings, file_path
        )

    return findings, files, routes, matched_traffic


def build_analysis_context(
    scan_result: dict,
    file_path: Optional[str] = None,
    burp_transactions: Optional[List[BurpTransaction]] = None,
    prompt: Optional[str] = None,
) -> dict:
    """Metadata about what the LLM will receive (for UI context panel)."""
    findings, files, routes, matched_traffic = _collect_analysis_scope(
        scan_result, file_path, burp_transactions
    )
    burp_loaded = len(burp_transactions or [])
    return {
        "scope": file_path or "all vulnerable files",
        "file_path": file_path,
        "findings_count": len(findings),
        "findings_in_prompt": min(len(findings), 40),
        "routes_count": len(routes),
        "routes_in_prompt": min(len(routes), 30),
        "source_files": files[:3],
        "burp_loaded": burp_loaded,
        "burp_in_prompt": min(len(matched_traffic), MAX_TRAFFIC_ITEMS),
        "burp_matched_routes": sum(1 for t in (burp_transactions or []) if t.matched_route_path),
        "uses_burp": burp_loaded > 0,
        "prompt_chars": len(prompt) if prompt is not None else None,
    }


def build_analysis_prompt(
    scan_result: dict,
    file_path: Optional[str] = None,
    burp_transactions: Optional[List[BurpTransaction]] = None,
    graphql_context: str = "",
) -> str:
    """Build the LLM prompt from scan findings, source, and Burp traffic."""
    findings, files, routes, matched_traffic = _collect_analysis_scope(
        scan_result, file_path, burp_transactions
    )

    findings_text = "\n\n".join(_format_finding(f) for f in findings[:40])
    if not findings_text:
        findings_text = "No findings in selected scope."

    source_sections = []
    for fp in files[:3]:
        source_sections.append(f"### {fp}\n```\n{_read_source(fp)}\n```")
    source_text = "\n\n".join(source_sections) if source_sections else "No source files in scope."

    traffic_text = _format_traffic(matched_traffic)
    correlation_hints = _build_correlation_hints(findings, matched_traffic, routes)
    burp_count = len(burp_transactions or [])
    traffic_in_prompt = len(matched_traffic)

    attack_surface = "\n".join(
        f"- {r.get('method', 'ALL')} {r.get('path')} "
        f"handler={r.get('source_file') or 'unknown'} "
        f"params={r.get('params')} auth={r.get('auth_middleware') or 'none'}"
        for r in routes[:30]
    )

    scope_label = file_path or "all vulnerable files"
    gql_block = f"\n{graphql_context}\n" if graphql_context else ""
    burp_instructions = ""
    if burp_count:
        burp_instructions = f"""
## Burp traffic is loaded ({burp_count} total requests; {traffic_in_prompt} included below)
You MUST use the Observed HTTP Traffic section. For every finding, either:
- Cite a specific **Burp request #N** (method, path, param, status, response snippet) that proves the endpoint is live, OR
- State explicitly that no Burp request matches and describe the exact request to capture in Burp Repeater.

Cross-reference rules:
1. Match `Linked route` / `Input param` from findings to Burp URL paths, query strings, and request bodies.
2. Match `Matched static route` on each Burp request to handler files in Attack Surface.
3. For client-side findings (XSS, DOM sinks, hardcoded secrets in UI code): identify which **HTML/JS/API Burp request** serves that file or passes the vulnerable value.
4. Quote response body snippets when they show reflection, errors, secrets, or auth behavior.
5. Do NOT invent endpoints or parameters — only use those present in findings, routes, or Burp data.
6. Do NOT give generic payload lists — each payload must target a named param on a named Burp request or route.
"""
    else:
        burp_instructions = """
## No Burp traffic loaded
Base exploitability on static routes and source code only. Note where live traffic capture is required.
"""

    return f"""You are an expert penetration tester performing code-assisted web app testing.

You have three evidence sources that must be synthesized — not analyzed in isolation:
1. **Static findings** — rule hits with exact file:line and scanner hints
2. **Source code** — real handlers, sinks, and data flow
3. **Burp HTTP traffic** — proof of live endpoints, real parameters, and server behavior
{burp_instructions}
## Analysis scope
{scope_label}

## Mandatory method (apply to EVERY finding)
For each static finding (by rule ID):
a) Quote the vulnerable **file:line** and **enclosing function** from Source Code.
b) Identify the **entry point**: HTTP method + path + parameter/header/cookie, OR the client-side trigger if SPA.
c) Find corroborating **Burp request #N** — use Pre-computed Finding ↔ Traffic Links and match URL, query, body params.
d) Trace **data flow**: entry → variables → sink (cite code lines).
e) Assess **exploitability** using Burp status code + response snippet (reflection, error, auth, secret exposure).
f) Give **one concrete test**: curl command or Burp Repeater edit referencing the real param and URL.

## Pre-computed Finding ↔ Traffic Links
{correlation_hints}

## Attack Surface (static route discovery)
{attack_surface or 'No routes discovered — many findings may be client-side; use Burp HTML/JS/API requests.'}

## Static Analysis Findings
{findings_text}

## Source Code
{source_text}

## Observed HTTP Traffic (Burp Suite)
{traffic_text}
{gql_block}
---

Respond in markdown using EXACTLY these sections:

## 1. Executive Summary
Top risks, whether Burp confirms live exposure, and highest-priority retest targets.

## 2. Exploitability Assessment
One subsection per finding: `### [RULE_ID] finding name`
For each: file:line, live in Burp (yes/no + request #), exploitability verdict, evidence quote.

## 3. Attack Paths
One block per finding using this EXACT template (required for UI parsing):

### Attack Path: [RULE_ID] short title — file:line
Confidence: high|medium|low
- Entry point: METHOD /path?param= (Burp request #N, or "not observed in Burp")
- Source: `file:line` in `functionName()`
- Data flow: describe param → variables → sink with line references
- Burp evidence: status code, what the response shows (quote snippet)
- Exploit step: specific payload on specific param
- Verify: curl command or Burp Repeater instruction

## 4. Burp Cross-Reference
Table or list mapping Burp request #N → matched route → handler file → related finding(s).
Note endpoints seen in Burp with no static finding (potential gaps).

## 5. Concrete Exploitation Steps
Numbered steps a pentester can run now. Every step must name file:line, URL, param, and Burp request #.

## 6. Prioritized Testing Checklist
Ordered checklist with finding ID, endpoint, and expected result.

Critical rules:
- Every claim must cite file:line and/or Burp request #N.
- Never output generic advice disconnected from the provided code and traffic.
- If a finding has no Burp match, say so and give the capture steps.
"""


def parse_attack_paths_from_markdown(text: str) -> List[dict]:
    """Extract attack path cards from LLM markdown (section 3 format)."""
    paths: List[dict] = []
    current: Dict[str, Any] = {}
    in_attack_section = False

    def _flush() -> None:
        nonlocal current
        if current.get("title") and (
            current.get("steps") or "attack path" in current.get("title", "").lower()
        ):
            paths.append(current)
        current = {}

    def _confidence_from_line(line: str) -> Optional[str]:
        lower = line.lower()
        if "confidence:" not in lower and "confidence" not in lower:
            return None
        if "high" in lower:
            return "high"
        if "low" in lower:
            return "low"
        return "medium"

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## 3.") or stripped.lower().startswith("## attack path"):
            in_attack_section = True
            continue
        if in_attack_section and stripped.startswith("## ") and not stripped.lower().startswith("## attack path"):
            _flush()
            in_attack_section = False

        is_path_header = (
            stripped.lower().startswith("### attack path:")
            or (stripped.startswith("### ") and in_attack_section)
        )
        if is_path_header:
            _flush()
            title = stripped.lstrip("#").strip()
            if title.lower().startswith("attack path:"):
                title = title.split(":", 1)[1].strip()
            current = {"title": title, "steps": [], "confidence": "medium"}

        conf = _confidence_from_line(stripped)
        if conf and current:
            current["confidence"] = conf
        elif current and (
            stripped.startswith("- ")
            or stripped.startswith("* ")
            or (len(stripped) > 2 and stripped[0].isdigit() and stripped[1] in ".)")
        ):
            step = stripped.lstrip("0123456789.) ").lstrip("-* ").strip()
            if step and not step.lower().startswith("confidence:"):
                current.setdefault("steps", []).append(step)

    _flush()

    if not paths and text.strip():
        paths.append({
            "title": "LLM Analysis",
            "steps": [text[:500]],
            "confidence": "medium",
        })
    return paths[:15]
