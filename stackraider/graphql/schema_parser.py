import re
from typing import Any

from graphql import build_client_schema, get_introspection_query
from graphql.type import (
    GraphQLEnumType,
    GraphQLInputObjectType,
    GraphQLInterfaceType,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLUnionType,
)
from graphql.type.definition import GraphQLAbstractType

from stackraider.web.schemas.graphql import (
    ParsedSchema,
    SchemaArgument,
    SchemaField,
    SchemaType,
)

SENSITIVE_ARG_PATTERNS = [
    (re.compile(r"\bid\b", re.I), "id"),
    (re.compile(r"url|uri|link|redirect|callback|webhook", re.I), "url"),
    (re.compile(r"file|path|filename|upload", re.I), "file"),
    (re.compile(r"sql|query|search|filter|where|raw", re.I), "sql_like"),
    (re.compile(r"token|secret|password|key|auth", re.I), "credential"),
]


def _unwrap_type(type_obj) -> tuple[str, bool, bool]:
    is_list = False
    is_required = False
    current = type_obj
    if isinstance(current, GraphQLNonNull):
        is_required = True
        current = current.of_type
    if isinstance(current, GraphQLList):
        is_list = True
        current = current.of_type
    if isinstance(current, GraphQLNonNull):
        is_required = True
        current = current.of_type
    name = current.name if hasattr(current, "name") else str(current)
    return name, is_list, is_required


def _iter_named(items) -> list[tuple[str, object]]:
    if isinstance(items, dict):
        return list(items.items())
    return [(getattr(item, "name", ""), item) for item in items or []]


def _parse_args(args) -> list[SchemaArgument]:
    result = []
    for name, arg in _iter_named(args):
        type_name, _, is_required = _unwrap_type(arg.type)
        default = None
        if arg.default_value is not None:
            default = str(arg.default_value)
        result.append(
            SchemaArgument(
                name=name,
                type_name=type_name,
                is_required=is_required,
                default_value=default,
            )
        )
    return result


def _parse_fields(fields, *, is_input: bool = False) -> list[SchemaField]:
    result = []
    for name, field in _iter_named(fields):
        type_name, is_list, is_required = _unwrap_type(field.type)
        # GraphQLInputField (input objects) has no .args — only GraphQLField does
        args = (
            []
            if is_input
            else _parse_args(getattr(field, "args", None))
        )
        result.append(
            SchemaField(
                name=name,
                type_name=type_name,
                is_list=is_list,
                is_required=is_required,
                is_deprecated=bool(getattr(field, "is_deprecated", False)),
                deprecation_reason=getattr(field, "deprecation_reason", None),
                args=args,
            )
        )
    return result


def _find_circular_refs(
    types: list[SchemaType],
    max_depth: int = 10,
    max_cycles: int = 20,
    max_visits: int = 8000,
) -> list[list[str]]:
    """Detect circular object references with strict bounds (large schemas can explode)."""
    type_map = {t.name: t for t in types if t.kind in ("OBJECT", "INTERFACE")}
    if not type_map:
        return []

    adjacency: dict[str, list[str]] = {}
    for name, t in type_map.items():
        adjacency[name] = list(
            dict.fromkeys(
                f.type_name for f in t.fields if f.type_name in type_map
            )
        )

    cycles: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    visits = 0

    def record_cycle(path: list[str]) -> None:
        if len(cycles) >= max_cycles:
            return
        key = tuple(path)
        if key not in seen:
            seen.add(key)
            cycles.append(path.copy())

    def walk(start: str, current: str, path: list[str], depth: int) -> None:
        nonlocal visits
        if len(cycles) >= max_cycles or visits >= max_visits or depth > max_depth:
            return
        visits += 1

        if current == start and len(path) >= 2:
            record_cycle(path + [start])
            return

        if current in path:
            return

        path.append(current)
        for nxt in adjacency.get(current, []):
            walk(start, nxt, path, depth + 1)
        path.pop()

    # Only start from types that can reach themselves within max_depth
    starters = list(type_map.keys())[:80]
    for name in starters:
        if len(cycles) >= max_cycles or visits >= max_visits:
            break
        walk(name, name, [], 0)

    return cycles


def _detect_sensitive_arguments(schema: ParsedSchema) -> list[dict[str, Any]]:
    sensitive = []
    all_ops = schema.queries + schema.mutations + schema.subscriptions
    for op in all_ops:
        for arg in op.args:
            for pattern, kind in SENSITIVE_ARG_PATTERNS:
                if pattern.search(arg.name):
                    sensitive.append(
                        {
                            "operation": op.name,
                            "argument": arg.name,
                            "type": arg.type_name,
                            "kind": kind,
                        }
                    )
                    break
    return sensitive


def _possible_type_names(schema, type_def: GraphQLAbstractType) -> list[str]:
    return [t.name for t in schema.get_possible_types(type_def)]


def _normalize_introspection(data: dict[str, Any]) -> dict[str, Any]:
    if "data" in data and "__schema" in data.get("data", {}):
        return data
    if "__schema" in data:
        return {"data": data}
    raise ValueError("Invalid introspection JSON: missing __schema")


def parse_introspection(raw: dict[str, Any]) -> ParsedSchema:
    normalized = _normalize_introspection(raw)
    schema = build_client_schema(normalized["data"])

    types: list[SchemaType] = []
    for type_def in schema.type_map.values():
        if type_def.name.startswith("__"):
            continue

        if isinstance(type_def, GraphQLObjectType):
            kind = "OBJECT"
            fields = _parse_fields(type_def.fields)
            enum_values = []
            possible_types = []
        elif isinstance(type_def, GraphQLInputObjectType):
            kind = "INPUT_OBJECT"
            fields = _parse_fields(type_def.fields, is_input=True)
            enum_values = []
            possible_types = []
        elif isinstance(type_def, GraphQLEnumType):
            kind = "ENUM"
            fields = []
            enum_values = [name for name, _ in _iter_named(type_def.values)]
            possible_types = []
        elif isinstance(type_def, GraphQLInterfaceType):
            kind = "INTERFACE"
            fields = _parse_fields(type_def.fields)
            enum_values = []
            possible_types = _possible_type_names(schema, type_def)
        elif isinstance(type_def, GraphQLUnionType):
            kind = "UNION"
            fields = []
            enum_values = []
            possible_types = _possible_type_names(schema, type_def)
        elif isinstance(type_def, GraphQLScalarType):
            kind = "SCALAR"
            fields = []
            enum_values = []
            possible_types = []
        else:
            continue

        types.append(
            SchemaType(
                name=type_def.name,
                kind=kind,
                description=type_def.description,
                fields=fields,
                enum_values=enum_values,
                possible_types=possible_types,
            )
        )

    types.sort(key=lambda t: t.name)

    query_type_name = schema.query_type.name if schema.query_type else None
    mutation_type_name = schema.mutation_type.name if schema.mutation_type else None
    subscription_type_name = (
        schema.subscription_type.name if schema.subscription_type else None
    )

    queries: list[SchemaField] = []
    mutations: list[SchemaField] = []
    subscriptions: list[SchemaField] = []

    for t in types:
        if t.name == query_type_name:
            queries = t.fields
        elif t.name == mutation_type_name:
            mutations = t.fields
        elif t.name == subscription_type_name:
            subscriptions = t.fields

    circular = _find_circular_refs(types)

    parsed = ParsedSchema(
        query_type=query_type_name,
        mutation_type=mutation_type_name,
        subscription_type=subscription_type_name,
        types=types,
        queries=queries,
        mutations=mutations,
        subscriptions=subscriptions,
        circular_references=circular,
        type_count=len(types),
        query_count=len(queries),
        mutation_count=len(mutations),
    )
    parsed.sensitive_arguments = _detect_sensitive_arguments(parsed)
    return parsed


def schema_to_summary(schema: ParsedSchema) -> str:
    lines = [
        f"Types: {schema.type_count}, Queries: {schema.query_count}, Mutations: {schema.mutation_count}",
        f"Query root: {schema.query_type}",
        f"Mutation root: {schema.mutation_type}",
    ]
    if schema.queries:
        lines.append("Queries: " + ", ".join(q.name for q in schema.queries[:30]))
    if schema.mutations:
        lines.append("Mutations: " + ", ".join(m.name for m in schema.mutations[:30]))
    if schema.circular_references:
        lines.append(f"Circular refs: {len(schema.circular_references)}")
    return "\n".join(lines)


def get_standard_introspection_query() -> str:
    return get_introspection_query()
