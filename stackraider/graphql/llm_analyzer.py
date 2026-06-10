import asyncio
import json
import re
import uuid
from collections.abc import Awaitable, Callable

from ollama import AsyncClient

from stackraider.web.schemas.graphql import (
    Finding,
    ParsedSchema,
    Severity,
    VulnerabilityCategory,
)
from stackraider.graphql.schema_parser import schema_to_summary

EmitFn = Callable[[dict], Awaitable[None]]

SYSTEM_PROMPT = """You are an expert GraphQL penetration tester and security auditor.
Analyze the provided GraphQL schema for security vulnerabilities.
Return ONLY a JSON array of findings. Each finding must have:
- title (string)
- description (string)
- severity: one of critical, high, medium, low, info
- category: one of information_disclosure, authorization, injection, dos, idor, batching, deprecated, business_logic
- affected_types (array of strings, optional)
- affected_fields (array of strings, optional)
- recommendation (string, optional)

Focus on: authorization bypass chains, business logic flaws, IDOR, injection, DoS via nested queries, sensitive data exposure, and exploitation paths.
Be specific to the schema provided. Do not repeat generic advice without tying it to actual types/fields."""

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

CATEGORY_MAP = {
    "information_disclosure": VulnerabilityCategory.INFORMATION_DISCLOSURE,
    "authorization": VulnerabilityCategory.AUTHORIZATION,
    "injection": VulnerabilityCategory.INJECTION,
    "dos": VulnerabilityCategory.DOS,
    "idor": VulnerabilityCategory.IDOR,
    "batching": VulnerabilityCategory.BATCHING,
    "deprecated": VulnerabilityCategory.DEPRECATED,
    "business_logic": VulnerabilityCategory.BUSINESS_LOGIC,
}


async def _emit(emit: EmitFn | None, level: str, message: str, **extra):
    if emit:
        await emit({"level": level, "message": message, **extra})


def _chunk_types(schema: ParsedSchema, chunk_size: int = 15) -> list[str]:
    chunks = []
    for i in range(0, len(schema.types), chunk_size):
        batch = schema.types[i : i + chunk_size]
        lines = []
        for t in batch:
            field_names = ", ".join(f.name for f in t.fields[:20])
            lines.append(f"- {t.name} ({t.kind}): {field_names}")
        chunks.append("\n".join(lines))
    return chunks


def _parse_llm_findings(text: str) -> list[Finding]:
    findings = []
    match = re.search(r"\[[\s\S]*\]", text)
    if not match:
        return findings
    try:
        data = json.loads(match.group())
    except json.JSONDecodeError:
        return findings

    if not isinstance(data, list):
        return findings

    for item in data:
        if not isinstance(item, dict):
            continue
        sev = SEVERITY_MAP.get(
            str(item.get("severity", "medium")).lower(), Severity.MEDIUM
        )
        cat = CATEGORY_MAP.get(
            str(item.get("category", "business_logic")).lower(),
            VulnerabilityCategory.BUSINESS_LOGIC,
        )
        findings.append(
            Finding(
                id=str(uuid.uuid4())[:8],
                title=item.get("title", "LLM finding"),
                description=item.get("description", ""),
                severity=sev,
                category=cat,
                affected_types=item.get("affected_types") or [],
                affected_fields=item.get("affected_fields") or [],
                source="llm",
                recommendation=item.get("recommendation"),
            )
        )
    return findings


async def _heartbeat(emit: EmitFn | None, label: str, stop: asyncio.Event) -> None:
    """Emit periodic status while waiting for the model."""
    elapsed = 0
    while not stop.is_set():
        await asyncio.sleep(3)
        if stop.is_set():
            break
        elapsed += 3
        await _emit(
            emit,
            "info",
            f"Still waiting on model ({label})... {elapsed}s elapsed "
            "(large models may load into memory on first request)",
        )


async def _stream_chat(
    client: AsyncClient,
    model: str,
    messages: list[dict],
    emit: EmitFn | None,
    batch_label: str,
) -> str:
    await _emit(emit, "llm", f"Model response ({batch_label}):", stream_start=True)
    await _emit(
        emit,
        "info",
        f"Sending prompt to `{model}` ({batch_label}) — waiting for first token...",
    )

    content_parts: list[str] = []
    stop = asyncio.Event()
    heartbeat_task = asyncio.create_task(_heartbeat(emit, batch_label, stop))

    try:
        stream = await client.chat(
            model=model,
            messages=messages,
            stream=True,
            options={"temperature": 0.3},
        )
        got_token = False
        async for part in stream:
            token = part.message.content if part.message else ""
            if token:
                if not got_token:
                    got_token = True
                    stop.set()
                    await _emit(emit, "success", f"Model is responding ({batch_label})...")
                content_parts.append(token)
                if emit:
                    await emit({"level": "llm", "message": "", "chunk": token})
    finally:
        stop.set()
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass

    token_count = len("".join(content_parts))
    await _emit(
        emit,
        "info",
        f"Finished batch: {batch_label} ({token_count} characters received)",
    )
    return "".join(content_parts)


OnBatchFn = Callable[[list[Finding]], Awaitable[None]]


async def analyze_with_llm(
    schema: ParsedSchema,
    host: str,
    model: str,
    emit: EmitFn | None = None,
    on_batch: OnBatchFn | None = None,
) -> tuple[list[Finding], bool]:
    client = AsyncClient(host=host)
    all_findings: list[Finding] = []

    summary = schema_to_summary(schema)
    type_chunks = _chunk_types(schema)
    total = len(type_chunks) or 1

    await _emit(emit, "info", f"Verifying Ollama connectivity at {host}...")
    await _emit(
        emit,
        "info",
        f"Model: `{model}` — {total} schema batch(es), "
        f"{len(schema.types)} types, {schema.query_count} queries, {schema.mutation_count} mutations",
    )

    for idx, chunk in enumerate(type_chunks or [""]):
        batch_label = f"batch {idx + 1}/{total}"
        type_lines = [ln for ln in chunk.split("\n") if ln.strip()]
        preview = ", ".join(
            ln.split(":")[0].replace("- ", "") for ln in type_lines[:5]
        )
        await _emit(
            emit,
            "info",
            f"LLM analyzing {batch_label}"
            + (f" — types: {preview}" if preview else "")
            + (f" (+{len(type_lines) - 5} more)" if len(type_lines) > 5 else ""),
        )

        user_prompt = f"""Schema summary:
{summary}

Types batch {idx + 1}/{total}:
{chunk}

Identify security vulnerabilities specific to these types and operations."""

        try:
            content = await _stream_chat(
                client,
                model,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                emit,
                batch_label,
            )
            batch_findings = _parse_llm_findings(content)
            all_findings.extend(batch_findings)
            if batch_findings:
                await _emit(
                    emit,
                    "success",
                    f"{batch_label}: extracted {len(batch_findings)} finding(s) from model output",
                )
                if on_batch:
                    await on_batch(batch_findings)
            else:
                await _emit(
                    emit,
                    "info",
                    f"{batch_label}: model returned no parseable findings "
                    "(output may not be valid JSON)",
                )
        except Exception as e:
            await _emit(emit, "error", f"Ollama request failed on {batch_label}: {e}")
            all_findings.append(
                Finding(
                    id=str(uuid.uuid4())[:8],
                    title="LLM analysis error",
                    description=f"Ollama request failed: {e}",
                    severity=Severity.INFO,
                    category=VulnerabilityCategory.BUSINESS_LOGIC,
                    source="llm",
                )
            )
            break

    if len(type_chunks) > 1 and all_findings:
        await _emit(emit, "info", "Consolidating findings across batches...")
        try:
            consolidate_prompt = f"""Consolidate these findings into a deduplicated JSON array (same format):
{json.dumps([f.model_dump() for f in all_findings], default=str)[:8000]}"""
            content = await _stream_chat(
                client,
                model,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": consolidate_prompt},
                ],
                emit,
                "consolidation",
            )
            consolidated = _parse_llm_findings(content)
            if consolidated:
                await _emit(
                    emit,
                    "success",
                    f"Consolidated to {len(consolidated)} unique finding(s)",
                )
                return consolidated, True
        except Exception as e:
            await _emit(emit, "error", f"Consolidation failed, using raw findings: {e}")

    return all_findings, False
