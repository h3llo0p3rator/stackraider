import asyncio
import json

from typing import Optional

from fastapi import APIRouter, Cookie
from sse_starlette.sse import EventSourceResponse

from stackraider.web.session import get_or_create_session, resolve_session_id

from stackraider.web.config import settings
from stackraider.web.schemas.graphql import AnalyzeRequest
from stackraider.graphql import (
    llm_analyzer,
    query_generator,
    schema_parser,
    static_analyzer,
)

router = APIRouter(prefix="/api/graphql", tags=["graphql"])

SSE_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}

PARSE_TIMEOUT_SEC = 120


@router.get("/state")
async def get_graphql_state(
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    _, state = get_or_create_session(resolve_session_id(stackraider_session, srcsniff_session))
    return {
        "schema": state.get("graphql_schema"),
        "findings": state.get("graphql_findings", []),
        "queries": state.get("graphql_queries", []),
    }


@router.post("/analyze")
async def analyze(
    request: AnalyzeRequest,
    stackraider_session: Optional[str] = Cookie(None),
    srcsniff_session: Optional[str] = Cookie(None),
):
    sid, session_state = get_or_create_session(
        resolve_session_id(stackraider_session, srcsniff_session)
    )

    async def event_generator():
        queue: asyncio.Queue = asyncio.Queue()
        sentinel = object()

        async def emit(entry: dict):
            await queue.put({"event": "log", "data": json.dumps(entry)})

        async def emit_queries_batch(batch: list) -> int:
            if not batch:
                return 0
            await queue.put(
                {
                    "event": "queries_batch",
                    "data": json.dumps(
                        [q.model_dump() for q in batch],
                        default=str,
                    ),
                }
            )
            return len(batch)

        async def parse_with_progress():
            parse_done = asyncio.Event()

            async def heartbeat():
                elapsed = 0
                while not parse_done.is_set():
                    await asyncio.sleep(3)
                    if parse_done.is_set():
                        break
                    elapsed += 3
                    await emit(
                        {
                            "level": "info",
                            "message": (
                                f"Still parsing schema... {elapsed}s "
                                "(building type graph and checking circular references)"
                            ),
                        }
                    )

            hb = asyncio.create_task(heartbeat())
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(
                        schema_parser.parse_introspection, request.introspection
                    ),
                    timeout=PARSE_TIMEOUT_SEC,
                )
            finally:
                parse_done.set()
                hb.cancel()
                try:
                    await hb
                except asyncio.CancelledError:
                    pass

        async def run():
            query_count = 0
            all_queries = []
            try:
                await emit({"level": "info", "message": "Analysis pipeline started"})
                await emit(
                    {
                        "level": "info",
                        "message": "Parsing introspection response (running in background thread)...",
                    }
                )

                try:
                    schema = await parse_with_progress()
                except asyncio.TimeoutError:
                    await emit(
                        {
                            "level": "error",
                            "message": (
                                f"Schema parsing timed out after {PARSE_TIMEOUT_SEC}s. "
                                "The introspection payload may be too large or complex."
                            ),
                        }
                    )
                    raise

                if schema.circular_references:
                    await emit(
                        {
                            "level": "info",
                            "message": (
                                f"Detected {len(schema.circular_references)} circular "
                                "type reference(s) in schema"
                            ),
                        }
                    )
                if schema.sensitive_arguments:
                    await emit(
                        {
                            "level": "info",
                            "message": (
                                f"Flagged {len(schema.sensitive_arguments)} sensitive "
                                "argument(s) during parse"
                            ),
                        }
                    )

                await queue.put(
                    {
                        "event": "schema",
                        "data": json.dumps(schema.model_dump(), default=str),
                    }
                )
                await emit(
                    {
                        "level": "success",
                        "message": (
                            f"Schema parsed — {schema.type_count} types, "
                            f"{schema.query_count} queries, {schema.mutation_count} mutations"
                        ),
                    }
                )
                session_state["graphql_schema"] = schema.model_dump()

                await emit({"level": "info", "message": "Running static security rules..."})

                async def static_step(msg: str):
                    await emit({"level": "info", "message": f"  → {msg}"})

                static_findings = await static_analyzer.analyze(
                    schema, on_step=static_step
                )

                await queue.put(
                    {
                        "event": "findings",
                        "data": json.dumps(
                            {
                                "source": "static",
                                "findings": [f.model_dump() for f in static_findings],
                            },
                            default=str,
                        ),
                    }
                )
                await emit(
                    {
                        "level": "success",
                        "message": f"Static analysis complete — {len(static_findings)} finding(s)",
                    }
                )

                all_findings = list(static_findings)
                dos_depth = request.dos_query_depth

                await emit(
                    {
                        "level": "info",
                        "message": (
                            f"Generating test queries from static findings "
                            f"(DoS depth: {dos_depth})..."
                        ),
                    }
                )
                for phase, batch in query_generator.iter_query_batches(
                    schema, static_findings, dos_depth, include_schema_wide=True
                ):
                    added = await emit_queries_batch(batch)
                    query_count += added
                    all_queries.extend([q.model_dump() for q in batch])
                    await emit(
                        {
                            "level": "success",
                            "message": (
                                f"+{added} test queries ({phase}) — "
                                f"{query_count} available so far"
                            ),
                        }
                    )

                host = request.ollama_host or settings.ollama_host
                model = request.model or settings.default_model

                async def on_llm_batch(batch_findings: list):
                    nonlocal query_count, all_queries
                    await queue.put(
                        {
                            "event": "findings",
                            "data": json.dumps(
                                {
                                    "source": "llm",
                                    "findings": [f.model_dump() for f in batch_findings],
                                },
                                default=str,
                            ),
                        }
                    )
                    new_queries = query_generator.generate_queries_for_findings(
                        schema, batch_findings, dos_depth
                    )
                    for i in range(0, len(new_queries), query_generator.BATCH_SIZE):
                        chunk = new_queries[i : i + query_generator.BATCH_SIZE]
                        added = await emit_queries_batch(chunk)
                        query_count += added
                        all_queries.extend([q.model_dump() for q in chunk])
                    if new_queries:
                        await emit(
                            {
                                "level": "success",
                                "message": (
                                    f"LLM batch: +{len(batch_findings)} finding(s), "
                                    f"+{len(new_queries)} test queries — "
                                    f"{query_count} total"
                                ),
                            }
                        )

                if not request.skip_llm:
                    await emit(
                        {
                            "level": "info",
                            "message": f"Starting LLM analysis with `{model}` at {host}...",
                        }
                    )
                    llm_findings, was_consolidated = await llm_analyzer.analyze_with_llm(
                        schema, host, model, emit=emit, on_batch=on_llm_batch
                    )
                    all_findings = list(static_findings) + llm_findings
                    if was_consolidated:
                        await queue.put(
                            {
                                "event": "findings",
                                "data": json.dumps(
                                    {
                                        "source": "llm_finalize",
                                        "findings": [f.model_dump() for f in llm_findings],
                                    },
                                    default=str,
                                ),
                            }
                        )
                    await emit(
                        {
                            "level": "success",
                            "message": f"LLM analysis complete — {len(llm_findings)} finding(s)",
                        }
                    )
                else:
                    await emit({"level": "info", "message": "LLM analysis skipped (settings)"})

                await queue.put(
                    {
                        "event": "complete",
                        "data": json.dumps(
                            {
                                "finding_count": len(all_findings),
                                "query_count": query_count,
                            }
                        ),
                    }
                )
                await emit(
                    {
                        "level": "success",
                        "message": (
                            f"Analysis complete — {len(all_findings)} findings, "
                            f"{query_count} test queries"
                        ),
                    }
                )
                session_state["graphql_findings"] = [f.model_dump() for f in all_findings]
                session_state["graphql_queries"] = all_queries
                session_state["latest_graphql_analysis"] = {
                    "finding_count": len(all_findings),
                    "query_count": query_count,
                    "session_id": sid,
                }
            except Exception as e:
                await emit({"level": "error", "message": str(e)})
                await queue.put({"event": "error", "data": json.dumps({"error": str(e)})})
            finally:
                await queue.put(sentinel)

        yield {
            "event": "log",
            "data": json.dumps({"level": "info", "message": "Server stream open — starting analysis..."}),
        }

        task = asyncio.create_task(run())
        try:
            while True:
                item = await queue.get()
                if item is sentinel:
                    break
                yield item
                await asyncio.sleep(0)
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    return EventSourceResponse(
        event_generator(),
        headers=SSE_HEADERS,
        ping=5,
    )
