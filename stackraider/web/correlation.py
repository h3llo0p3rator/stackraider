"""Cross-module correlation between code scan and GraphQL analysis."""

from __future__ import annotations

from typing import Any, Dict, List


def build_graphql_context_for_code_prompt(state: dict) -> str:
    """Summary of GraphQL session data for code LLM prompt."""
    findings = state.get("graphql_findings") or []
    schema = state.get("graphql_schema")
    if not findings and not schema:
        return ""

    lines = [
        "## GraphQL Schema Analysis (loaded in this session)",
        "Cross-reference code GraphQL findings (GQL-* rules) with this live schema data.",
    ]
    if schema:
        lines.append(
            f"Schema: {schema.get('type_count', 0)} types, "
            f"{schema.get('query_count', 0)} queries, "
            f"{schema.get('mutation_count', 0)} mutations"
        )
    for f in findings[:15]:
        title = f.get("title", "Finding")
        sev = f.get("severity", "")
        cat = f.get("category", "")
        types = ", ".join(f.get("affected_types", [])[:3])
        fields = ", ".join(f.get("affected_fields", [])[:3])
        lines.append(f"- [{sev}] {title} ({cat}) types={types} fields={fields}")
    if len(findings) > 15:
        lines.append(f"... and {len(findings) - 15} more GraphQL findings")
    return "\n".join(lines)


def correlate_findings(state: dict) -> List[Dict[str, Any]]:
    """Map code GraphQL rule hits to GraphQL schema findings."""
    scan = state.get("scan_result")
    gql_findings = state.get("graphql_findings") or []
    if not scan or not gql_findings:
        return []

    code_gql = [
        f for f in scan.get("findings", [])
        if f.get("rule_id", "").startswith("GQL-")
        or "graphql" in f.get("category", "").lower()
    ]
    links: List[Dict[str, Any]] = []
    for cf in code_gql:
        snippet = (cf.get("line_content") or "").lower()
        related = []
        for gf in gql_findings:
            haystack = " ".join([
                gf.get("title", ""),
                gf.get("description", ""),
                " ".join(gf.get("affected_types", [])),
                " ".join(gf.get("affected_fields", [])),
            ]).lower()
            overlap = any(
                word in haystack
                for word in snippet.split()
                if len(word) > 4 and word.isalnum()
            )
            if overlap or any(
                t.lower() in snippet
                for t in gf.get("affected_types", [])
            ):
                related.append({
                    "id": gf.get("id"),
                    "title": gf.get("title"),
                    "severity": gf.get("severity"),
                })
        links.append({
            "code_rule": cf.get("rule_id"),
            "code_file": cf.get("file_path"),
            "code_line": cf.get("line_number"),
            "graphql_findings": related[:5],
        })
    return links
