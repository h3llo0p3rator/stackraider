import re
import uuid
from collections.abc import Awaitable, Callable

from stackraider.web.schemas.graphql import (
    Finding,
    ParsedSchema,
    Severity,
    VulnerabilityCategory,
)

ADMIN_PATTERNS = re.compile(
    r"admin|internal|debug|secret|private|hidden|backdoor|system|root|superuser",
    re.I,
)
AUTH_ARG_PATTERNS = re.compile(
    r"token|auth|bearer|apikey|api_key|session|jwt|credential|password",
    re.I,
)
ID_PATTERNS = re.compile(r"\bid\b|uuid|user_?id|account_?id|owner", re.I)
URL_PATTERNS = re.compile(r"url|uri|link|redirect|callback|webhook|endpoint", re.I)
STRING_TYPES = {"String", "ID"}


def _fid() -> str:
    return str(uuid.uuid4())[:8]


StepCallback = Callable[[str], Awaitable[None]]


async def analyze(
    schema: ParsedSchema, on_step: StepCallback | None = None
) -> list[Finding]:
    findings: list[Finding] = []

    async def step(msg: str) -> None:
        if on_step:
            await on_step(msg)

    await step("Checking introspection exposure...")
    findings.append(
        Finding(
            id=_fid(),
            title="Introspection schema exposed",
            description="The introspection response was successfully parsed, indicating introspection is enabled or schema data was obtained.",
            severity=Severity.MEDIUM,
            category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
            affected_types=[schema.query_type or "Query"],
            source="static",
            recommendation="Disable introspection in production or restrict it to authenticated developers.",
        )
    )

    await step(f"Scanning {schema.type_count} types for sensitive names and deprecated fields...")
    for t in schema.types:
        if ADMIN_PATTERNS.search(t.name):
            findings.append(
                Finding(
                    id=_fid(),
                    title=f"Sensitive type name: {t.name}",
                    description=f"Type `{t.name}` suggests internal or privileged data may be exposed.",
                    severity=Severity.HIGH,
                    category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                    affected_types=[t.name],
                    source="static",
                    recommendation="Review authorization on resolvers for this type.",
                )
            )

        for field in t.fields:
            if field.is_deprecated:
                findings.append(
                    Finding(
                        id=_fid(),
                        title=f"Deprecated field still present: {t.name}.{field.name}",
                        description=field.deprecation_reason
                        or "Deprecated fields may remain functional and leak legacy behavior.",
                        severity=Severity.LOW,
                        category=VulnerabilityCategory.DEPRECATED,
                        affected_types=[t.name],
                        affected_fields=[field.name],
                        source="static",
                    )
                )

            if ADMIN_PATTERNS.search(field.name):
                findings.append(
                    Finding(
                        id=_fid(),
                        title=f"Sensitive field name: {t.name}.{field.name}",
                        description="Field name suggests privileged or debug data.",
                        severity=Severity.MEDIUM,
                        category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                        affected_types=[t.name],
                        affected_fields=[field.name],
                        source="static",
                    )
                )

    await step(f"Reviewing {schema.mutation_count} mutations for authorization concerns...")
    for mutation in schema.mutations:
        has_auth_arg = any(AUTH_ARG_PATTERNS.search(a.name) for a in mutation.args)
        if ADMIN_PATTERNS.search(mutation.name) or (
            not has_auth_arg and mutation.args
        ):
            sev = Severity.HIGH if ADMIN_PATTERNS.search(mutation.name) else Severity.MEDIUM
            findings.append(
                Finding(
                    id=_fid(),
                    title=f"Mutation authorization concern: {mutation.name}",
                    description="Mutation lacks obvious auth-related arguments or has admin-like naming.",
                    severity=sev,
                    category=VulnerabilityCategory.AUTHORIZATION,
                    affected_fields=[mutation.name],
                    source="static",
                    recommendation="Verify resolver-level authorization; do not rely on obscurity.",
                )
            )

    await step(
        f"Analyzing {schema.query_count} queries and {schema.mutation_count} mutations "
        "for injection, SSRF, and IDOR surfaces..."
    )
    for op in schema.queries + schema.mutations:
        for arg in op.args:
            if arg.type_name in STRING_TYPES or "String" in arg.type_name:
                if not URL_PATTERNS.search(arg.name):
                    findings.append(
                        Finding(
                            id=_fid(),
                            title=f"Injection surface: {op.name}({arg.name})",
                            description=f"String argument `{arg.name}` on `{op.name}` may accept injection payloads.",
                            severity=Severity.MEDIUM,
                            category=VulnerabilityCategory.INJECTION,
                            affected_fields=[f"{op.name}.{arg.name}"],
                            source="static",
                        )
                    )
            if URL_PATTERNS.search(arg.name):
                findings.append(
                    Finding(
                        id=_fid(),
                        title=f"SSRF surface: {op.name}({arg.name})",
                        description=f"URL-like argument `{arg.name}` may enable server-side request forgery.",
                        severity=Severity.HIGH,
                        category=VulnerabilityCategory.INJECTION,
                        affected_fields=[f"{op.name}.{arg.name}"],
                        source="static",
                    )
                )
            if ID_PATTERNS.search(arg.name) and arg.type_name in ("ID", "String", "Int"):
                findings.append(
                    Finding(
                        id=_fid(),
                        title=f"IDOR candidate: {op.name}({arg.name})",
                        description=f"ID argument `{arg.name}` may allow accessing other users' objects.",
                        severity=Severity.HIGH,
                        category=VulnerabilityCategory.IDOR,
                        affected_fields=[f"{op.name}.{arg.name}"],
                        source="static",
                    )
                )

    await step(f"Checking {len(schema.circular_references)} circular reference(s) for DoS risk...")
    for cycle in schema.circular_references[:5]:
        findings.append(
            Finding(
                id=_fid(),
                title="Circular type reference (DoS)",
                description=f"Circular reference detected: {' -> '.join(cycle)}. Enables deeply nested query bombs.",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.DOS,
                affected_types=cycle,
                source="static",
                recommendation="Enforce query depth and complexity limits.",
            )
        )

    await step("Scanning for nested list returns and pagination abuse...")
    for t in schema.types:
        for field in t.fields:
            if field.is_list and field.type_name in {x.name for x in schema.types}:
                inner = next((x for x in t.fields if x.name == field.name), None)
                if inner and inner.is_list:
                    findings.append(
                        Finding(
                            id=_fid(),
                            title=f"Nested list return: {t.name}.{field.name}",
                            description="List-of-complex-type fields can amplify query cost.",
                            severity=Severity.MEDIUM,
                            category=VulnerabilityCategory.DOS,
                            affected_types=[t.name],
                            affected_fields=[field.name],
                            source="static",
                        )
                    )

    await step("Checking alias / batching abuse potential...")
    if schema.queries or schema.mutations:
        findings.append(
            Finding(
                id=_fid(),
                title="Alias / batching abuse possible",
                description="GraphQL supports aliases and batched operations; test for rate-limit bypass with duplicated aliased fields.",
                severity=Severity.MEDIUM,
                category=VulnerabilityCategory.BATCHING,
                source="static",
                recommendation="Rate-limit by query complexity, not just request count.",
            )
        )

    await step("Reviewing pagination arguments...")
    pagination_ops = [
        q.name
        for q in schema.queries
        if any(a.name in ("first", "limit", "take", "offset", "skip") for a in q.args)
    ]
    for name in pagination_ops:
        findings.append(
            Finding(
                id=_fid(),
                title=f"Unbounded pagination: {name}",
                description="Pagination arguments without documented max limits may allow large data extraction.",
                severity=Severity.LOW,
                category=VulnerabilityCategory.DOS,
                affected_fields=[name],
                source="static",
            )
        )

    return findings
