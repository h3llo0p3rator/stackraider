import uuid
from collections.abc import Iterator

from stackraider.web.schemas.graphql import (
    Finding,
    GeneratedQuery,
    ParsedSchema,
    Severity,
    VulnerabilityCategory,
)

MAX_QUERIES = 80
BATCH_SIZE = 8


def _qid() -> str:
    return str(uuid.uuid4())[:8]


def _format_args(args: list, payload: str | None = None) -> str:
    if not args:
        return ""
    parts = []
    for a in args[:3]:
        if a.type_name in ("String", "ID"):
            val = f'"{payload or "test"}"' if payload else '"test"'
        elif a.type_name == "Int":
            val = "1"
        elif a.type_name == "Boolean":
            val = "true"
        else:
            val = "{}"
        parts.append(f"{a.name}: {val}")
    return "(" + ", ".join(parts) + ")"


def _select_fields(type_name: str, schema: ParsedSchema, depth: int = 1) -> str:
    t = next((x for x in schema.types if x.name == type_name), None)
    if not t or depth <= 0:
        return "id"
    fields = []
    for f in t.fields[:5]:
        if f.type_name in {x.name for x in schema.types if x.kind == "OBJECT"}:
            nested = _select_fields(f.type_name, schema, depth - 1)
            fields.append(f"{f.name} {{ {nested} }}")
        else:
            fields.append(f.name)
    return " ".join(fields) if fields else "id"


def _circular_nest(field_a: str, field_b: str, depth: int, indent: int = 2) -> str:
    pad = "  " * indent
    if depth <= 1:
        return f"{pad}{field_a} {{ id }}"
    return (
        f"{pad}{field_a} {{\n"
        f"{_circular_nest(field_b, field_a, depth - 1, indent + 1)}\n"
        f"{pad}}}"
    )


def _chunked(items: list[GeneratedQuery], size: int = BATCH_SIZE) -> Iterator[list[GeneratedQuery]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _circular_queries(
    schema: ParsedSchema, findings: list[Finding], depth: int
) -> list[GeneratedQuery]:
    queries: list[GeneratedQuery] = []
    dos_finding = next(
        (f for f in findings if f.category == VulnerabilityCategory.DOS), None
    )
    for cycle in schema.circular_references[:3]:
        if len(cycle) < 2:
            continue
        a, b = cycle[0], cycle[1]
        ta = next((t for t in schema.types if t.name == a), None)
        tb = next((t for t in schema.types if t.name == b), None)
        if not ta or not tb:
            continue
        fa = next((f for f in ta.fields if f.type_name == b), ta.fields[0] if ta.fields else None)
        fb = next((f for f in tb.fields if f.type_name == a), tb.fields[0] if tb.fields else None)
        if fa and fb:
            nest = _circular_nest(fa.name, fb.name, depth)
            queries.append(
                GeneratedQuery(
                    id=_qid(),
                    title=f"Circular reference DoS (depth {depth}): {a} <-> {b}",
                    query=f"""query CircularDoS {{
  node {{
    ... on {a} {{
{nest}
    }}
  }}
}}""",
                    vulnerability="Query depth / circular reference bomb",
                    expected_behavior="Server timeout or high CPU if depth limits are absent.",
                    severity=Severity.HIGH,
                    category=VulnerabilityCategory.DOS,
                    finding_id=dos_finding.id if dos_finding else None,
                )
            )
    return queries


def _batching_queries(
    schema: ParsedSchema, findings: list[Finding], depth: int
) -> list[GeneratedQuery]:
    if not schema.queries:
        return []
    batch_finding = next(
        (f for f in findings if f.category == VulnerabilityCategory.BATCHING), None
    )
    q0 = schema.queries[0]
    sel = _select_fields(q0.type_name, schema, min(depth, 3))
    aliases = [f"  a{i}: {q0.name} {{ {sel} }}" for i in range(10)]
    return [
        GeneratedQuery(
            id=_qid(),
            title="Alias batching / rate-limit bypass",
            query="query BatchAliases {\n" + "\n".join(aliases) + "\n}",
            vulnerability="Rate limit bypass via aliased duplicate fields",
            expected_behavior="Single HTTP request triggers multiple resolver executions.",
            severity=Severity.MEDIUM,
            category=VulnerabilityCategory.BATCHING,
            finding_id=batch_finding.id if batch_finding else None,
        )
    ]


def _injection_queries(schema: ParsedSchema, findings: list[Finding]) -> list[GeneratedQuery]:
    queries: list[GeneratedQuery] = []
    payloads = [
        ("' OR '1'='1", "SQL injection probe"),
        ('{"$gt": ""}', "NoSQL injection probe"),
        ("${7*7}", "Template injection probe"),
    ]
    for op in (schema.queries + schema.mutations)[:15]:
        str_args = [a for a in op.args if a.type_name in ("String", "ID")]
        for arg in str_args[:1]:
            for payload, label in payloads:
                args_str = _format_args(op.args, payload.replace('"', '\\"'))
                sel = _select_fields(op.type_name, schema) if op in schema.queries else "id success"
                op_kind = "query" if op in schema.queries else "mutation"
                field_key = f"{op.name}.{arg.name}"
                related = next(
                    (
                        f
                        for f in findings
                        if f.category == VulnerabilityCategory.INJECTION
                        and field_key in f.affected_fields
                    ),
                    None,
                )
                queries.append(
                    GeneratedQuery(
                        id=_qid(),
                        title=f"{label}: {op.name}.{arg.name}",
                        query=f"""{op_kind} InjectionTest {{
  {op.name}{args_str} {{
    {sel}
  }}
}}""",
                        vulnerability=label,
                        expected_behavior="Errors or data leakage indicating unsanitized input handling.",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.INJECTION,
                        finding_id=related.id if related else None,
                    )
                )
    return queries


def _idor_queries(schema: ParsedSchema, findings: list[Finding]) -> list[GeneratedQuery]:
    queries: list[GeneratedQuery] = []
    for op in schema.queries + schema.mutations:
        id_args = [
            a
            for a in op.args
            if a.name.lower() in ("id", "userid", "user_id") or a.type_name == "ID"
        ]
        for arg in id_args[:1]:
            for test_id in ("1", "2", "999999"):
                args_parts = [
                    f"{a.name}: {test_id}" if a.name == arg.name else f'{a.name}: "test"'
                    for a in op.args[:3]
                ]
                args_str = "(" + ", ".join(args_parts) + ")" if args_parts else ""
                sel = _select_fields(op.type_name, schema)
                field_key = f"{op.name}.{arg.name}"
                related = next(
                    (
                        f
                        for f in findings
                        if f.category == VulnerabilityCategory.IDOR
                        and field_key in f.affected_fields
                    ),
                    None,
                )
                queries.append(
                    GeneratedQuery(
                        id=_qid(),
                        title=f"IDOR probe id={test_id}: {op.name}",
                        query=f"""query IDORTest {{
  {op.name}{args_str} {{
    {sel}
  }}
}}""",
                        vulnerability="Insecure direct object reference",
                        expected_behavior="Access to another user's resource without authorization.",
                        severity=Severity.HIGH,
                        category=VulnerabilityCategory.IDOR,
                        finding_id=related.id if related else None,
                    )
                )
    return queries


def _mutation_queries(schema: ParsedSchema, findings: list[Finding]) -> list[GeneratedQuery]:
    queries: list[GeneratedQuery] = []
    for mutation in schema.mutations[:10]:
        t = next((x for x in schema.types if x.name == mutation.type_name), None)
        sel = " ".join(f.name for f in t.fields[:10]) if t else "id"
        args_str = _format_args(mutation.args)
        related = next(
            (
                f
                for f in findings
                if f.category == VulnerabilityCategory.AUTHORIZATION
                and mutation.name in f.affected_fields
            ),
            None,
        )
        queries.append(
            GeneratedQuery(
                id=_qid(),
                title=f"Mutation abuse: {mutation.name}",
                query=f"""mutation AbuseMutation {{
  {mutation.name}{args_str} {{
    {sel or "id"}
  }}
}}""",
                vulnerability="Unauthorized mutation execution",
                expected_behavior="Mutation succeeds without proper authorization.",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.AUTHORIZATION,
                finding_id=related.id if related else None,
            )
        )
    return queries


def _finding_dos_queries(
    schema: ParsedSchema, findings: list[Finding], depth: int
) -> list[GeneratedQuery]:
    queries: list[GeneratedQuery] = []
    for finding in findings:
        if finding.category != VulnerabilityCategory.DOS or not finding.affected_types:
            continue
        tname = finding.affected_types[0]
        t = next((x for x in schema.types if x.name == tname), None)
        if not t or not t.fields:
            continue
        f = t.fields[0]
        nested = _select_fields(f.type_name, schema, depth)
        queries.append(
            GeneratedQuery(
                id=_qid(),
                title=f"Deep nesting (depth {depth}): {finding.title[:50]}",
                query=f"""query DeepNest {{
  probe {{
    ... on {tname} {{
      {f.name} {{
        {nested}
      }}
    }}
  }}
}}""",
                vulnerability="Deep query DoS",
                expected_behavior="Server resource exhaustion.",
                severity=finding.severity,
                category=finding.category,
                finding_id=finding.id,
            )
        )
    return queries


def _introspection_query(findings: list[Finding]) -> list[GeneratedQuery]:
    info_finding = next(
        (f for f in findings if f.category == VulnerabilityCategory.INFORMATION_DISCLOSURE),
        None,
    )
    return [
        GeneratedQuery(
            id=_qid(),
            title="Introspection probe",
            query="""query IntrospectionProbe {
  __schema {
    types { name kind }
    queryType { name }
    mutationType { name }
  }
}""",
            vulnerability="Schema information disclosure",
            expected_behavior="Full schema returned if introspection is enabled.",
            severity=Severity.MEDIUM,
            category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
            finding_id=info_finding.id if info_finding else None,
        )
    ]


def iter_query_batches(
    schema: ParsedSchema,
    findings: list[Finding],
    dos_depth: int = 3,
    *,
    include_schema_wide: bool = True,
) -> Iterator[tuple[str, list[GeneratedQuery]]]:
    """Yield (phase_label, queries) batches for progressive streaming."""
    depth = max(2, min(20, dos_depth))
    total = 0

    def emit(phase: str, items: list[GeneratedQuery]) -> Iterator[tuple[str, list[GeneratedQuery]]]:
        nonlocal total
        if not items or total >= MAX_QUERIES:
            return
        remaining = MAX_QUERIES - total
        items = items[:remaining]
        total += len(items)
        for batch in _chunked(items):
            yield phase, batch

    if include_schema_wide:
        yield from emit("circular_dos", _circular_queries(schema, findings, depth))
        yield from emit("batching", _batching_queries(schema, findings, depth))
        yield from emit("injection", _injection_queries(schema, findings))
        yield from emit("idor", _idor_queries(schema, findings))
        yield from emit("mutations", _mutation_queries(schema, findings))
        yield from emit("introspection", _introspection_query(findings))

    yield from emit("finding_dos", _finding_dos_queries(schema, findings, depth))


def generate_queries_for_findings(
    schema: ParsedSchema,
    findings: list[Finding],
    dos_depth: int = 3,
) -> list[GeneratedQuery]:
    """Generate queries only for specific findings (e.g. new LLM batch)."""
    depth = max(2, min(20, dos_depth))
    return _finding_dos_queries(schema, findings, depth)[:MAX_QUERIES]


def generate_queries(
    schema: ParsedSchema,
    findings: list[Finding],
    dos_depth: int = 3,
) -> list[GeneratedQuery]:
    all_queries: list[GeneratedQuery] = []
    for _, batch in iter_query_batches(schema, findings, dos_depth):
        all_queries.extend(batch)
    return all_queries[:MAX_QUERIES]
