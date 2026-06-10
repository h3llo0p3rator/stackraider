from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(str, Enum):
    INFORMATION_DISCLOSURE = "information_disclosure"
    AUTHORIZATION = "authorization"
    INJECTION = "injection"
    DOS = "dos"
    IDOR = "idor"
    BATCHING = "batching"
    DEPRECATED = "deprecated"
    BUSINESS_LOGIC = "business_logic"


class SchemaArgument(BaseModel):
    name: str
    type_name: str
    is_required: bool = False
    default_value: str | None = None


class SchemaField(BaseModel):
    name: str
    type_name: str
    is_list: bool = False
    is_required: bool = False
    is_deprecated: bool = False
    deprecation_reason: str | None = None
    args: list[SchemaArgument] = Field(default_factory=list)


class SchemaType(BaseModel):
    name: str
    kind: str
    description: str | None = None
    fields: list[SchemaField] = Field(default_factory=list)
    enum_values: list[str] = Field(default_factory=list)
    possible_types: list[str] = Field(default_factory=list)


class ParsedSchema(BaseModel):
    query_type: str | None = None
    mutation_type: str | None = None
    subscription_type: str | None = None
    types: list[SchemaType] = Field(default_factory=list)
    queries: list[SchemaField] = Field(default_factory=list)
    mutations: list[SchemaField] = Field(default_factory=list)
    subscriptions: list[SchemaField] = Field(default_factory=list)
    circular_references: list[list[str]] = Field(default_factory=list)
    sensitive_arguments: list[dict[str, Any]] = Field(default_factory=list)
    type_count: int = 0
    query_count: int = 0
    mutation_count: int = 0


class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    category: VulnerabilityCategory
    affected_types: list[str] = Field(default_factory=list)
    affected_fields: list[str] = Field(default_factory=list)
    source: str = "static"  # static | llm
    recommendation: str | None = None


class GeneratedQuery(BaseModel):
    id: str
    title: str
    query: str
    vulnerability: str
    expected_behavior: str
    severity: Severity
    category: VulnerabilityCategory
    finding_id: str | None = None


class AnalyzeRequest(BaseModel):
    introspection: dict[str, Any]
    model: str | None = None
    ollama_host: str | None = None
    skip_llm: bool = False
    dos_query_depth: int = Field(default=3, ge=2, le=20)


class ChatContext(BaseModel):
    schema_summary: str | None = None
    findings_summary: str | None = None
    queries_summary: str | None = None


class ModelInfo(BaseModel):
    name: str
    size: int | None = None
    parameter_size: str | None = None
    quantization: str | None = None
    family: str | None = None
    modified_at: str | None = None


class RecommendedModel(BaseModel):
    name: str
    description: str
    size_hint: str


class PullProgress(BaseModel):
    status: str
    digest: str | None = None
    total: int | None = None
    completed: int | None = None
    percent: float | None = None
