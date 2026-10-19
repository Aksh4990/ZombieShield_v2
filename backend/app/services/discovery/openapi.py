"""OpenAPI 3.x and Swagger 2.0 parsing into a flat list of operations."""

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


class SpecError(ValueError):
    pass


@dataclass
class SpecOperation:
    method: str
    path: str
    deprecated: bool = False
    security: list[str] = field(default_factory=list)  # scheme names; empty list = explicitly public
    security_declared: bool = False
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    parameter_names: list[str] = field(default_factory=list)
    property_names: list[str] = field(default_factory=list)


@dataclass
class ParsedSpec:
    title: str
    version: str
    host: str | None
    format: str  # openapi3 | swagger2
    operations: list[SpecOperation]


def load_document(document: str | bytes) -> dict:
    if isinstance(document, bytes):
        document = document.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(document)
    except json.JSONDecodeError:
        try:
            parsed = yaml.safe_load(document)
        except yaml.YAMLError as exc:
            raise SpecError("Document is not valid JSON or YAML") from exc
    if not isinstance(parsed, dict):
        raise SpecError("Specification must be a JSON/YAML object")
    return parsed


def _resolve(document: dict, node, depth: int = 0):
    if depth > 8 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        target = document
        for part in ref[2:].split("/"):
            if not isinstance(target, dict):
                return {}
            target = target.get(part.replace("~1", "/").replace("~0", "~"), {})
        return _resolve(document, target, depth + 1)
    return node


def _schema_properties(document: dict, schema, out: set[str], depth: int = 0) -> None:
    schema = _resolve(document, schema)
    if depth > 4 or not isinstance(schema, dict):
        return
    for name, child in (schema.get("properties") or {}).items():
        out.add(str(name))
        _schema_properties(document, child, out, depth + 1)
    if isinstance(schema.get("items"), dict):
        _schema_properties(document, schema["items"], out, depth + 1)
    for key in ("allOf", "oneOf", "anyOf"):
        for child in schema.get(key) or []:
            _schema_properties(document, child, out, depth + 1)


def _operation_properties(document: dict, operation: dict) -> list[str]:
    names: set[str] = set()
    body = _resolve(document, operation.get("requestBody") or {})
    for media in (body.get("content") or {}).values():
        if isinstance(media, dict):
            _schema_properties(document, media.get("schema"), names)
    for parameter in operation.get("parameters") or []:
        parameter = _resolve(document, parameter)
        if isinstance(parameter, dict) and parameter.get("in") == "body":
            _schema_properties(document, parameter.get("schema"), names)
    for response in (operation.get("responses") or {}).values():
        response = _resolve(document, response)
        if not isinstance(response, dict):
            continue
        if "schema" in response:
            _schema_properties(document, response.get("schema"), names)
        for media in (response.get("content") or {}).values():
            if isinstance(media, dict):
                _schema_properties(document, media.get("schema"), names)
    return sorted(names)


def _security_names(requirements) -> list[str]:
    names = []
    for requirement in requirements or []:
        if isinstance(requirement, dict):
            names.extend(str(key) for key in requirement.keys())
    return sorted(set(names))


def parse_spec(document: str | bytes | dict, *, include_properties: bool = False) -> ParsedSpec:
    parsed = document if isinstance(document, dict) else load_document(document)
    openapi_version = str(parsed.get("openapi", ""))
    swagger_version = str(parsed.get("swagger", ""))
    if openapi_version.startswith("3."):
        spec_format = "openapi3"
    elif swagger_version.startswith("2."):
        spec_format = "swagger2"
    else:
        raise SpecError("Document must be an OpenAPI 3.x or Swagger 2.0 specification")
    paths = parsed.get("paths")
    if not isinstance(paths, dict):
        raise SpecError("Specification must contain a paths object")

    info = parsed.get("info") if isinstance(parsed.get("info"), dict) else {}
    host = None
    base_path = ""
    if spec_format == "openapi3":
        servers = parsed.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict) and isinstance(servers[0].get("url"), str):
            url = urlparse(servers[0]["url"])
            host = url.netloc or None
            base_path = url.path.rstrip("/") if url.netloc else servers[0]["url"].rstrip("/")
            if "{" in base_path:
                base_path = ""
    else:
        host = parsed.get("host") if isinstance(parsed.get("host"), str) else None
        base_path = str(parsed.get("basePath") or "").rstrip("/")

    global_security = parsed.get("security")
    operations: list[SpecOperation] = []
    for path, item in paths.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(item, dict):
            continue
        item = _resolve(parsed, item)
        path_deprecated = bool(item.get("deprecated") or item.get("x-deprecated"))
        shared_params = [p.get("name") for p in (item.get("parameters") or []) if isinstance(_resolve(parsed, p), dict) and isinstance(_resolve(parsed, p).get("name"), str)]
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            declared = "security" in operation or global_security is not None
            security = _security_names(operation.get("security", global_security))
            params = list(shared_params)
            for parameter in operation.get("parameters") or []:
                parameter = _resolve(parsed, parameter)
                if isinstance(parameter, dict) and isinstance(parameter.get("name"), str):
                    params.append(parameter["name"])
            operations.append(SpecOperation(
                method=method.upper(),
                path=(base_path + path) if base_path and base_path != "/" else path,
                deprecated=path_deprecated or bool(operation.get("deprecated") or operation.get("x-deprecated")),
                security=security,
                security_declared=declared,
                summary=str(operation.get("summary") or operation.get("operationId") or ""),
                tags=[str(tag) for tag in operation.get("tags") or []],
                parameter_names=sorted(set(str(p) for p in params if p)),
                property_names=_operation_properties(parsed, operation) if include_properties else [],
            ))
    return ParsedSpec(
        title=str(info.get("title") or "api"),
        version=str(info.get("version") or "").strip() or "unversioned",
        host=host,
        format=spec_format,
        operations=operations,
    )
