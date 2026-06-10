#!/usr/bin/env python3
"""StackRaider CLI — scan, web UI, and GraphQL audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def cmd_scan(forward: list[str]) -> int:
    from stackraider.core.scanner import main

    sys.argv = ["stackraider"] + forward
    return main()


def cmd_web(path: str | None, port: int, open_browser: bool) -> int:
    try:
        from stackraider.web.server import start
    except ImportError as e:
        print(f"Web UI requires dependencies. Run: pip install -r requirements.txt\n  {e}")
        return 1
    if path and not Path(path).exists():
        print(f"Error: Path does not exist: {path}")
        return 1
    start(path=path, port=port, open_browser=open_browser)
    return 0


def cmd_graphql(file: str, use_llm: bool, model: str | None) -> int:
    from stackraider.graphql import query_generator, schema_parser, static_analyzer
    from stackraider.web.config import settings

    path = Path(file)
    if not path.exists():
        print(f"Error: File not found: {file}", file=sys.stderr)
        return 1

    raw = json.loads(path.read_text(encoding="utf-8"))
    introspection = raw.get("data", raw)
    schema = schema_parser.parse_introspection(introspection)

    import asyncio

    findings = asyncio.get_event_loop().run_until_complete(static_analyzer.analyze(schema))
    queries = []
    for _, batch in query_generator.iter_query_batches(schema, findings, dos_depth=3):
        queries.extend([q.model_dump() for q in batch])

    if use_llm:
        from stackraider.graphql import llm_analyzer

        async def run_llm():
            llm_findings, _ = await llm_analyzer.analyze_with_llm(
                schema,
                settings.ollama_host,
                model or settings.default_model,
            )
            return llm_findings

        llm_findings = asyncio.get_event_loop().run_until_complete(run_llm())
        findings = list(findings) + llm_findings
        for batch_findings in [llm_findings]:
            for q in query_generator.generate_queries_for_findings(schema, batch_findings, 3):
                queries.append(q.model_dump())

    out = {
        "schema": schema.model_dump(),
        "findings": [f.model_dump() for f in findings],
        "queries": queries,
    }
    print(json.dumps(out, indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="stackraider",
        description="StackRaider — offline pentest platform (code scan, Burp, GraphQL, LLM)",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Static code security scan", add_help=False)
    scan_p.add_argument("scan_args", nargs=argparse.REMAINDER)

    web_p = sub.add_parser("web", help="Launch unified web UI")
    web_p.add_argument("path", nargs="?", help="Default scan path")
    web_p.add_argument("--port", type=int, default=8000)
    web_p.add_argument("--no-browser", action="store_true")

    gql_p = sub.add_parser("graphql", help="Audit GraphQL introspection JSON")
    gql_p.add_argument("--file", "-f", required=True, help="Introspection JSON file")
    gql_p.add_argument("--llm", action="store_true", help="Include Ollama LLM analysis")
    gql_p.add_argument("--model", default=None, help="Ollama model name")

    if not argv:
        parser.print_help()
        return 0

    # Bare path or flags without subcommand → treat as scan
    if argv[0] not in ("scan", "web", "graphql", "-h", "--help"):
        return cmd_scan(argv)

    args = parser.parse_args(argv)

    if args.command == "scan":
        forward = list(args.scan_args)
        if forward and forward[0] == "--":
            forward = forward[1:]
        return cmd_scan(forward)

    if args.command == "web":
        return cmd_web(args.path, args.port, not args.no_browser)

    if args.command == "graphql":
        return cmd_graphql(args.file, args.llm, args.model)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
