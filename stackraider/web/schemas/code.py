"""Pydantic models for code-scan API routes."""

from typing import Optional

from pydantic import BaseModel

from stackraider.web.config import DEFAULT_OLLAMA_HOST


class ScanRequest(BaseModel):
    path: str
    severity: str = "INFO"
    exclude_rules: Optional[str] = None
    include_vendor: bool = False
    unminify: bool = False
    workers: int = 4


class CodeAnalyzeRequest(BaseModel):
    model: str
    file_path: Optional[str] = None
    scope: str = "file"
    ollama_host: str = DEFAULT_OLLAMA_HOST


class BurpConfigRequest(BaseModel):
    burp_jar: str
