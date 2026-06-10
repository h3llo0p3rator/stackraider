"""Parse Burp Suite exports: XML, HAR, and .burp project files."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class BurpTransaction:
    """One HTTP transaction from a Burp history export."""
    url: str
    host: str
    port: str
    protocol: str
    method: str
    path: str
    status: str
    mimetype: str
    time: str = ""
    request_raw: str = ""
    response_raw: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_body: str = ""
    matched_route_path: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _text(elem) -> str:
    return (elem.text or "").strip() if elem is not None else ""


def _decode_element(elem) -> str:
    if elem is None:
        return ""
    raw = elem.text or ""
    if elem.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return raw


def _split_http_message(raw: str) -> Tuple[Dict[str, str], str]:
    if not raw:
        return {}, ""
    parts = raw.split("\r\n\r\n", 1)
    if len(parts) == 1:
        parts = raw.split("\n\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    headers: Dict[str, str] = {}
    lines = header_block.splitlines()
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers, body


def parse_har(content: bytes | str) -> List[BurpTransaction]:
    """Parse HTTP Archive (HAR) JSON export from Burp or browsers."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    data = json.loads(content)
    entries = data.get("log", {}).get("entries", [])
    transactions: List[BurpTransaction] = []

    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = req.get("url", "")
        parsed = urlparse(url)
        protocol = parsed.scheme or "http"
        host = parsed.hostname or ""
        port = str(parsed.port or (443 if protocol == "https" else 80))
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        req_headers = {h["name"]: h["value"] for h in req.get("headers", []) if "name" in h}
        resp_headers = {h["name"]: h["value"] for h in resp.get("headers", []) if "name" in h}
        req_body = (req.get("postData") or {}).get("text", "") or ""
        resp_body = (resp.get("content") or {}).get("text", "") or ""
        mimetype = (resp.get("content") or {}).get("mimeType", "")

        transactions.append(BurpTransaction(
            url=url,
            host=host,
            port=port,
            protocol=protocol,
            method=(req.get("method") or "GET").upper(),
            path=path,
            status=str(resp.get("status", "")),
            mimetype=mimetype,
            time=entry.get("startedDateTime", ""),
            request_headers=req_headers,
            response_headers=resp_headers,
            request_body=req_body[:4000],
            response_body=resp_body[:4000],
        ))
    return transactions


def _find_burp_jar(override: Optional[str] = None) -> Optional[str]:
    candidates = [
        override,
        os.environ.get("BURP_JAR"),
        "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar",
        os.path.expanduser("~/BurpSuitePro/burpsuite_pro.jar"),
        os.path.expanduser("~/burpsuite_pro.jar"),
    ]
    for path in candidates:
        if path and Path(path).expanduser().is_file():
            return str(Path(path).expanduser().resolve())
    return None


def validate_burp_jar(path: str) -> str:
    """Resolve and validate a Burp JAR path. Raises ValueError if invalid."""
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"JAR file not found: {path}")
    if resolved.suffix.lower() != ".jar":
        raise ValueError("Path must point to a .jar file")
    return str(resolved)


def _headers_to_raw(headers: object, body: str = "") -> str:
    if isinstance(headers, str):
        return headers
    if isinstance(headers, list):
        lines = []
        for h in headers:
            if isinstance(h, dict):
                lines.append(f"{h.get('name', '')}: {h.get('value', '')}")
            else:
                lines.append(str(h))
        return "\r\n".join(lines) + ("\r\n\r\n" + body if body else "")
    if isinstance(headers, dict):
        lines = [f"{k}: {v}" for k, v in headers.items()]
        return "\r\n".join(lines) + ("\r\n\r\n" + body if body else "")
    return body


def _transaction_from_burp_json(obj: dict) -> Optional[BurpTransaction]:
    """Convert burpsuite-project-file-parser NDJSON line to BurpTransaction."""
    req = obj.get("request") or obj
    resp = obj.get("response") or {}

    url = req.get("url") or obj.get("url") or ""
    if not url:
        return None

    parsed = urlparse(url)
    protocol = parsed.scheme or "http"
    host = parsed.hostname or req.get("host") or ""
    port = str(parsed.port or req.get("port") or (443 if protocol == "https" else 80))
    path = req.get("uri") or parsed.path or "/"
    if parsed.query and "?" not in path:
        path = f"{path}?{parsed.query}"

    method = (req.get("method") or obj.get("method") or "GET").upper()
    status = str(resp.get("status") or resp.get("statusCode") or obj.get("status") or "")

    req_body = req.get("body") or ""
    if isinstance(req_body, bytes):
        req_body = req_body.decode("utf-8", errors="replace")
    resp_body = resp.get("body") or ""
    if isinstance(resp_body, bytes):
        resp_body = resp_body.decode("utf-8", errors="replace")

    req_raw = _headers_to_raw(req.get("headers"), str(req_body))
    resp_raw = _headers_to_raw(resp.get("headers"), str(resp_body))

    mimetype = resp.get("mimeType") or resp.get("mimetype") or ""
    if not mimetype and isinstance(resp.get("headers"), dict):
        mimetype = resp["headers"].get("Content-Type", "")

    return BurpTransaction(
        url=url,
        host=host,
        port=port,
        protocol=protocol,
        method=method,
        path=path,
        status=status,
        mimetype=mimetype,
        request_raw=req_raw[:8000],
        response_raw=resp_raw[:8000],
        request_headers=req.get("headers") if isinstance(req.get("headers"), dict) else {},
        response_headers=resp.get("headers") if isinstance(resp.get("headers"), dict) else {},
        request_body=str(req_body)[:4000],
        response_body=str(resp_body)[:4000],
    )


def parse_burp_project(
    project_path: str,
    burp_jar: Optional[str] = None,
    timeout: int = 300,
) -> List[BurpTransaction]:
    """Parse a .burp project file via Burp Suite + project-file-parser extension."""
    jar = _find_burp_jar(burp_jar)
    if not jar:
        raise ValueError(
            "Cannot read .burp files without Burp Suite Pro. Browse to your "
            "burpsuite_pro.jar below, install the burpsuite-project-file-parser extension, "
            "or export from Burp as XML/HAR: Proxy → HTTP history → Save items."
        )

    project_path = str(Path(project_path).resolve())
    java = shutil.which("java")
    if not java:
        raise ValueError("Java is required to read .burp project files.")

    cmd = [
        java,
        "-Djava.awt.headless=true",
        "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "-Xmx2G",
        "-jar", jar,
        f"--project-file={project_path}",
        "proxyHistory.request.headers,proxyHistory.response.headers",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        raise ValueError("Timed out parsing .burp file (project may be very large).")

    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or proc.stdout or "").strip()[:500]
        raise ValueError(
            f"Burp failed to parse project file. Ensure burpsuite-project-file-parser "
            f"extension is installed in Burp. {err}"
        )

    transactions: List[BurpTransaction] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            txn = _transaction_from_burp_json(obj)
            if txn:
                transactions.append(txn)
        except json.JSONDecodeError:
            continue

    if not transactions:
        raise ValueError(
            "No proxy history found in .burp file. Export XML/HAR from Burp instead, "
            "or ensure the project contains proxy traffic and the parser extension is installed."
        )
    return transactions


def parse_burp_upload(
    content: bytes,
    filename: str,
    burp_jar: Optional[str] = None,
) -> List[BurpTransaction]:
    """Parse uploaded Burp export by extension and content sniffing."""
    name = (filename or "").lower()
    stripped = content.lstrip()

    if name.endswith(".har") or stripped[:1] == b"{":
        return parse_har(content)

    if name.endswith(".xml") or stripped[:5] in (b"<?xml", b"<items"):
        return parse_burp_xml(content)

    if name.endswith(".burp"):
        with tempfile.NamedTemporaryFile(suffix=".burp", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            return parse_burp_project(tmp_path, burp_jar=burp_jar)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # Last resort: try XML then HAR
    try:
        return parse_burp_xml(content)
    except ET.ParseError:
        pass
    try:
        return parse_har(content)
    except json.JSONDecodeError:
        pass

    raise ValueError(
        "Unrecognized file format. Upload a Burp .burp project, XML export, or HAR file."
    )


def parse_burp_xml(content: bytes | str) -> List[BurpTransaction]:
    """Parse Burp Suite HTTP history XML into transaction objects."""
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    root = ET.fromstring(content)
    transactions: List[BurpTransaction] = []

    for item in root.findall("item"):
        host_elem = item.find("host")
        host = _text(host_elem)
        req_raw = _decode_element(item.find("request"))
        resp_raw = _decode_element(item.find("response"))
        req_headers, req_body = _split_http_message(req_raw)
        resp_headers, resp_body = _split_http_message(resp_raw)

        transactions.append(BurpTransaction(
            url=_text(item.find("url")),
            host=host,
            port=_text(item.find("port")),
            protocol=_text(item.find("protocol")),
            method=_text(item.find("method")).upper(),
            path=_text(item.find("path")),
            status=_text(item.find("status")),
            mimetype=_text(item.find("mimetype")),
            time=_text(item.find("time")),
            request_raw=req_raw[:8000],
            response_raw=resp_raw[:8000],
            request_headers=req_headers,
            response_headers=resp_headers,
            request_body=req_body[:4000],
            response_body=resp_body[:4000],
        ))
    return transactions


def _normalize_path(path: str) -> str:
    path = path.split("?")[0].rstrip("/") or "/"
    path = re.sub(r"/\d+", "/:id", path)
    path = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/:id", path, flags=re.I)
    return path.lower()


def _route_pattern(path: str) -> re.Pattern:
    pattern = re.escape(path.rstrip("/") or "/")
    pattern = pattern.replace(r"\:id", r"[^/]+")
    pattern = pattern.replace(r"\*", r"[^/]+")
    return re.compile(f"^{pattern}/?$", re.I)


def match_traffic_to_routes(
    transactions: List[BurpTransaction],
    routes: List[dict],
) -> Tuple[List[BurpTransaction], Dict[str, List[str]]]:
    """Match Burp traffic to discovered routes. Returns updated transactions and route->url map."""
    route_map: Dict[str, List[str]] = {}

    for txn in transactions:
        txn_path = _normalize_path(txn.path or txn.url.split("?", 1)[0].split("/", 3)[-1] if txn.url else "")
        if not txn_path.startswith("/"):
            txn_path = "/" + txn_path.split("/", 1)[-1] if "/" in txn_path else "/" + txn_path

        for route in routes:
            route_path = route.get("path", "")
            route_method = (route.get("method") or "ALL").upper()
            if route_method not in ("ALL", txn.method):
                continue
            norm_route = _normalize_path(route_path)
            if norm_route == txn_path or _route_pattern(route_path).match(txn.path or txn_path):
                txn.matched_route_path = route_path
                route_map.setdefault(route_path, []).append(txn.url)
                break

    return transactions, route_map


def summarize_traffic(transactions: List[BurpTransaction]) -> dict:
    matched = sum(1 for t in transactions if t.matched_route_path)
    return {
        "total": len(transactions),
        "matched_routes": matched,
        "methods": sorted({t.method for t in transactions}),
        "hosts": sorted({t.host for t in transactions if t.host}),
    }
