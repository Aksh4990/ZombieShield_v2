"""Access-log parsing: gateway JSON, nginx/Apache combined, and the simple legacy format."""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import unquote

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_COMBINED = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?(?:\s+(?P<latency>[\d.]+))?'
)
_SIMPLE = re.compile(r"^\s*(?P<ts>\S+)?\s*(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?P<uri>/\S*)(?:\s+(?P<status>\d{3}))?\s*$")


@dataclass
class LogRecord:
    ts: datetime | None
    method: str
    path: str  # without query string
    query: str
    status: int
    bytes_sent: int | None = None
    latency_ms: float | None = None
    client: str | None = None
    host: str | None = None
    service: str | None = None
    authenticated: bool | None = None
    user_agent: str | None = None


def _parse_ts(value) -> datetime | None:
    if value in (None, "", "-"):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value)
    for parser in (
        lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")),
        lambda v: datetime.strptime(v, "%d/%b/%Y:%H:%M:%S %z"),
    ):
        try:
            parsed = parser(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _split_uri(uri: str) -> tuple[str, str]:
    path, _, query = uri.partition("?")
    path = unquote(path) or "/"
    if path.startswith("http://") or path.startswith("https://"):
        path = "/" + path.split("/", 3)[-1] if path.count("/") >= 3 else "/"
    return path, query


def _from_json(data: dict) -> LogRecord | None:
    method = str(data.get("method") or data.get("request_method") or "").upper()
    uri = data.get("uri") or data.get("request_uri") or data.get("path") or data.get("url")
    if method not in METHODS or not isinstance(uri, str):
        request = data.get("request")
        if isinstance(request, str) and " " in request:
            parts = request.split()
            method, uri = parts[0].upper(), parts[1]
        if method not in METHODS or not isinstance(uri, str):
            return None
    path, query = _split_uri(uri)
    try:
        status = int(data.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    latency = data.get("latency") if data.get("latency") is not None else data.get("request_time")
    try:
        latency_ms = float(latency) * 1000 if latency not in (None, "", "-") else None
    except (TypeError, ValueError):
        latency_ms = None
    auth = data.get("auth")
    authenticated = None if auth in (None, "", "-") else str(auth) in {"1", "true", "True", "yes"}
    try:
        bytes_sent = int(data.get("bytes") or data.get("body_bytes_sent") or 0)
    except (TypeError, ValueError):
        bytes_sent = None
    return LogRecord(
        ts=_parse_ts(data.get("ts") or data.get("time") or data.get("timestamp") or data.get("time_iso8601")),
        method=method, path=path, query=query, status=status, bytes_sent=bytes_sent, latency_ms=latency_ms,
        client=str(data.get("client") or data.get("remote_addr") or data.get("ip") or "") or None,
        host=str(data.get("host") or "") or None,
        service=str(data.get("service") or "") or None,
        authenticated=authenticated,
        user_agent=str(data.get("ua") or data.get("user_agent") or "") or None,
    )


def parse_line(line: str) -> LogRecord | None:
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        return _from_json(data) if isinstance(data, dict) else None
    match = _COMBINED.match(line)
    if match and match["method"] in METHODS:
        path, query = _split_uri(match["uri"])
        latency = match["latency"]
        return LogRecord(
            ts=_parse_ts(match["ts"]), method=match["method"], path=path, query=query, status=int(match["status"]),
            bytes_sent=None if match["bytes"] == "-" else int(match["bytes"]),
            latency_ms=float(latency) * 1000 if latency else None,
            client=match["client"], user_agent=match["ua"],
        )
    match = _SIMPLE.match(line)
    if match:
        path, query = _split_uri(match["uri"])
        return LogRecord(ts=_parse_ts(match["ts"]), method=match["method"], path=path, query=query, status=int(match["status"] or 0))
    return None


def parse_lines(content: str) -> tuple[list[LogRecord], int]:
    records, skipped = [], 0
    for line in content.splitlines():
        if not line.strip():
            continue
        record = parse_line(line)
        if record is None:
            skipped += 1
        else:
            records.append(record)
    return records, skipped
