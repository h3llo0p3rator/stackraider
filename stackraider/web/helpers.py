"""Shared helpers for web API routes."""

from __future__ import annotations

from dataclasses import asdict
from typing import List

from stackraider.core.scanner import ScanResult
from stackraider.web.burp_parser import BurpTransaction


def scan_result_to_dict(result: ScanResult) -> dict:
    return {
        "scan_time": result.scan_time,
        "target_path": result.target_path,
        "files_scanned": result.files_scanned,
        "total_findings": result.total_findings,
        "findings_by_severity": result.findings_by_severity,
        "findings_by_category": result.findings_by_category,
        "scan_duration_seconds": result.scan_duration_seconds,
        "findings_with_route": result.findings_with_route,
        "findings_with_param": result.findings_with_param,
        "findings": [asdict(f) for f in result.findings],
        "routes": [asdict(r) for r in result.all_routes],
    }


def burp_to_dict(transactions: List[BurpTransaction]) -> List[dict]:
    return [
        {
            "url": t.url,
            "host": t.host,
            "method": t.method,
            "path": t.path,
            "status": t.status,
            "mimetype": t.mimetype,
            "matched_route_path": t.matched_route_path,
            "request_body": t.request_body[:300],
            "response_body": t.response_body[:300],
        }
        for t in transactions
    ]
