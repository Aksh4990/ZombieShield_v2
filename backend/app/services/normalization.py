"""Endpoint identity: one canonical template per operation, whatever the evidence source."""

import hashlib
import re

# {name}, {name:regex}, :name, <conv:name>, <name>, and a bare * wildcard all denote a path parameter.
_PARAM_PATTERNS = [
    re.compile(r"^\{[^}]+\}$"),
    re.compile(r"^:[A-Za-z_][\w-]*\??$"),
    re.compile(r"^<(?:[A-Za-z_]+:)?[A-Za-z_][\w]*>$"),
    re.compile(r"^\*$"),
]
_VERSION_SEGMENT = re.compile(r"^v\d+(?:\.\d+)?$", re.IGNORECASE)
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_ID = re.compile(r"^[0-9a-fA-F]{16,}$")
_MIXED_ID = re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{10,}$")
_EMAIL = re.compile(r"^[^@/]+@[^@/]+\.[^@/]+$")
PARAM = "{id}"


def is_param_segment(segment: str) -> bool:
    return any(pattern.match(segment) for pattern in _PARAM_PATTERNS)


def _split(path: str) -> list[str]:
    path = path.split("?", 1)[0].split("#", 1)[0]
    return [segment for segment in path.split("/") if segment]


def normalize_path(path: str) -> str:
    """Canonical template: no query, no trailing slash, every parameter rendered as {id}."""
    segments = [PARAM if is_param_segment(segment) else segment for segment in _split(path)]
    return "/" + "/".join(segments) if segments else "/"


def display_path(path: str) -> str:
    """Human-friendly template that keeps parameter names but unifies their syntax."""
    out = []
    for segment in _split(path):
        if segment.startswith(":"):
            out.append("{" + segment[1:].rstrip("?") + "}")
        elif segment.startswith("<") and segment.endswith(">"):
            out.append("{" + segment[1:-1].split(":")[-1] + "}")
        elif segment.startswith("{") and ":" in segment:
            out.append(segment.split(":", 1)[0] + "}")
        else:
            out.append(segment)
    return "/" + "/".join(out) if out else "/"


def version_from_path(path: str) -> str:
    for segment in _split(path):
        if _VERSION_SEGMENT.match(segment):
            return segment.lower()
    return "unversioned"


def resource_key(path: str) -> str:
    """Path with its version segment removed: /v1/customers/{id} and /v2/customers/{id} share a resource."""
    segments = [segment for segment in _split(normalize_path(path)) if not _VERSION_SEGMENT.match(segment)]
    return "/" + "/".join(segments)


def version_number(version: str) -> float:
    match = re.match(r"v(\d+(?:\.\d+)?)", version or "", re.IGNORECASE)
    return float(match.group(1)) if match else -1.0


def canonical_key(organization: str, host: str, method: str, path: str) -> str:
    identity = "\x1f".join((organization.strip().lower(), host.strip().lower(), method.upper(), normalize_path(path)))
    return hashlib.sha256(identity.encode()).hexdigest()


def looks_like_identifier(segment: str) -> bool:
    return bool(segment.isdigit() or _UUID.match(segment) or _HEX_ID.match(segment) or _MIXED_ID.match(segment) or _EMAIL.match(segment))


def template_runtime_path(raw_path: str, known_templates: list[str] | None = None) -> tuple[str, str | None]:
    """Map an observed request path to a template, returning (template, object-identifier segment).

    Known templates from specifications or source code win; otherwise identifier-looking
    segments (numbers, UUIDs, long hex or mixed tokens, e-mail addresses) become {id}.
    """
    segments = _split(raw_path)
    if known_templates:
        exact = [t for t in known_templates if not t.endswith("*")]
        prefixes = [t for t in known_templates if t.endswith("*")]
        for template in exact:
            template_segments = _split(template)
            if len(template_segments) != len(segments):
                continue
            captured = None
            for observed, expected in zip(segments, template_segments):
                if expected == PARAM:
                    captured = observed
                    continue
                if observed != expected:
                    break
            else:
                return template, captured
        observed = "/" + "/".join(segments)
        for template in sorted(prefixes, key=len, reverse=True):
            stem = template[:-1].rstrip("/")
            if observed == stem or observed.startswith(stem + "/") or (not template[:-1].endswith("/") and observed.startswith(template[:-1])):
                tail = observed[len(stem):].strip("/").split("/")
                return template, (tail[0] if tail and tail[0] else None)
    captured_id = None
    out = []
    for segment in segments:
        if looks_like_identifier(segment):
            out.append(PARAM)
            captured_id = segment
        else:
            out.append(segment)
    return ("/" + "/".join(out) if out else "/"), captured_id
