"""Shared, dependency-free feature helpers for the ML models (importable by training scripts)."""

import re
from urllib.parse import parse_qsl, unquote_plus

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_VERSION = re.compile(r"^v(\d+)(?:\.\d+)?$", re.I)
_SAFE_SEGMENT = re.compile(r"^[\w.\-~{}@]+$")
# A value made only of these characters cannot carry SQL/script/command/traversal syntax.
_INERT_VALUE = re.compile(r"^[A-Za-z0-9 _.,@+-]{0,80}$")


def is_inert(value: str) -> bool:
    return bool(_INERT_VALUE.match(value)) and "--" not in value

# Field-name tokens / compounds that indicate personal data or secrets. Matching is on whole
# name tokens (snake/camel split) so that e.g. 'nextToken' or 'ipAddress' are NOT flagged.
SENSITIVE_TOKENS = {"password", "passwd", "pwd", "secret", "email", "phone", "ssn", "iban", "cvv", "cvc", "passport", "salary", "birthdate", "dob", "birthday", "gender"}
SENSITIVE_COMPOUNDS = {
    "apikey", "accesstoken", "refreshtoken", "idtoken", "authtoken", "clientsecret", "cardnumber", "creditcard", "accountnumber",
    "routingnumber", "bankaccount", "dateofbirth", "firstname", "lastname", "fullname", "postalcode", "zipcode", "streetaddress",
    "homeaddress", "billingaddress", "shippingaddress", "nationalid", "taxid", "socialsecuritynumber", "mobilenumber", "phonenumber",
    "emailaddress",
}
SENSITIVE_TERMS = SENSITIVE_TOKENS | SENSITIVE_COMPOUNDS


def path_tokens(method: str, path: str) -> list[str]:
    """Tokens describing an endpoint using only what runtime traffic can see: method + path template."""
    tokens = [f"method_{method.lower()}"]
    segments = [s for s in path.split("/") if s]
    tokens.append(f"depth_{min(len(segments), 8)}")
    params = 0
    for position, segment in enumerate(segments):
        if segment.startswith("{") or segment.startswith(":") or segment.startswith("<"):
            params += 1
            tokens.append("param")
            if position == len(segments) - 1:
                tokens.append("ends_with_param")
            continue
        version = _VERSION.match(segment)
        if version:
            number = int(version.group(1))
            tokens.append("has_version")
            tokens.append(f"version_{min(number, 5)}")
            continue
        for part in _SPLIT.split(_CAMEL.sub("_", segment)):
            if part:
                tokens.append(part.lower())
    tokens.append(f"params_{min(params, 4)}")
    return tokens


def tokens_to_text(tokens: list[str]) -> str:
    return " ".join(tokens)


def is_sensitive_name(name: str) -> bool:
    parts = [part for part in _SPLIT.split(_CAMEL.sub("_", name).lower()) if part]
    if not parts:
        return False
    if any(part in SENSITIVE_TOKENS for part in parts):
        return True
    compact = "".join(parts)
    return compact in SENSITIVE_COMPOUNDS or any(compact.endswith(c) for c in SENSITIVE_COMPOUNDS)


def payload_text(path: str, query: str, body: str | None = None) -> str:
    """Values the payload classifier inspects: parameter values plus any unusual path segment.

    Parameter names and ordinary path segments are excluded so the model does not learn
    the vocabulary of one particular application (the CSIC data comes from a single shop).
    """
    values: list[str] = []
    for chunk in (query or "", body or ""):
        if not chunk:
            continue
        try:
            pairs = parse_qsl(chunk, keep_blank_values=True, errors="replace")
        except ValueError:
            pairs = []
        if pairs:
            values.extend(value for _, value in pairs)
        else:
            values.append(unquote_plus(chunk, errors="replace"))
    for segment in path.split("/"):
        decoded = unquote_plus(segment, errors="replace")
        if decoded and not _SAFE_SEGMENT.match(decoded):
            values.append(decoded)
    return " ".join(v for v in values if v and not is_inert(v))


LEGACY_FEATURES = ("newer_version_exists", "has_version", "path_version", "versions_in_service", "resource_versions", "is_delete")


def legacy_features(method: str, newer_version_exists: bool, path_version: float, versions_in_service: int, resource_versions: int) -> list[float]:
    """Structural features for P(legacy); available both for documented and runtime-only endpoints."""
    return [
        float(bool(newer_version_exists)),
        float(path_version >= 0),
        float(min(max(path_version, -1.0), 5.0)),
        float(min(max(versions_in_service, 0), 6)),
        float(min(max(resource_versions, 1), 4)),
        float(method.upper() == "DELETE"),
    ]
