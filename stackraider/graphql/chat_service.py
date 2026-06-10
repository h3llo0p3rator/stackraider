from ollama import AsyncClient

from stackraider.web.schemas.graphql import ChatContext, Finding, GeneratedQuery, ParsedSchema
from stackraider.graphql.schema_parser import schema_to_summary

CHAT_SYSTEM = """You are StackRaider, an expert GraphQL penetration testing assistant.
Help the user brainstorm attack ideas, explain vulnerabilities, refine exploit queries, and suggest remediation.
Be practical, specific, and security-focused. When generating GraphQL queries, format them in code blocks.
If schema context is provided, reference actual types, fields, and findings from that schema."""


def build_system_message(
    schema: ParsedSchema | None,
    findings: list[Finding] | None,
    queries: list[GeneratedQuery] | None,
    extra_context: ChatContext | None = None,
) -> str:
    parts = [CHAT_SYSTEM]

    if schema:
        parts.append("\n## Current Schema\n" + schema_to_summary(schema))
        if schema.sensitive_arguments:
            parts.append(
                "Sensitive arguments: "
                + ", ".join(
                    f"{s['operation']}.{s['argument']}" for s in schema.sensitive_arguments[:20]
                )
            )

    if findings:
        parts.append("\n## Findings")
        for f in findings[:25]:
            parts.append(f"- [{f.severity.value}] {f.title}: {f.description[:200]}")

    if queries:
        parts.append("\n## Generated Test Queries")
        for q in queries[:10]:
            parts.append(f"- {q.title}\n```graphql\n{q.query[:500]}\n```")

    if extra_context:
        if extra_context.schema_summary:
            parts.append("\n" + extra_context.schema_summary)
        if extra_context.findings_summary:
            parts.append("\n" + extra_context.findings_summary)

    return "\n".join(parts)


async def stream_chat(
    host: str,
    model: str,
    messages: list[dict],
    schema: ParsedSchema | None = None,
    findings: list[Finding] | None = None,
    queries: list[GeneratedQuery] | None = None,
    extra_system: str = "",
):
    client = AsyncClient(host=host)
    system = build_system_message(schema, findings, queries)
    if extra_system:
        system += extra_system
    full_messages = [{"role": "system", "content": system}] + messages

    stream = await client.chat(
        model=model,
        messages=full_messages,
        stream=True,
        options={"temperature": 0.6},
    )
    async for part in stream:
        if part.message and part.message.content:
            yield part.message.content
