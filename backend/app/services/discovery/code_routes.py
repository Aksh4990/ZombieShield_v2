"""Static route extraction from source code.

Supported frameworks (regular-expression based, deliberately transparent):
  * Python  - FastAPI (APIRouter prefixes, api_route), Flask (Blueprint url_prefix)
  * JS/TS   - Express (Router, app.use prefixes across files, route().get chains)
  * Java    - Spring MVC (class-level @RequestMapping + @Get/Post/...Mapping)
  * Go      - gorilla/mux (incl. PathPrefix subrouters), gin/echo groups, chi, net/http (1.22 patterns)
"""

import re
from dataclasses import dataclass
from pathlib import Path

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", "target", "vendor", "test", "tests"}
SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".java", ".kt", ".go"}


@dataclass(frozen=True)
class CodeRoute:
    method: str
    path: str
    file: str
    line: int
    framework: str
    note: str = ""


def _join(prefix: str, path: str) -> str:
    prefix = (prefix or "").rstrip("/")
    path = path or ""
    if not path.startswith("/") and path:
        path = "/" + path
    joined = prefix + path
    return joined or "/"


def _line_of(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


# ---------------------------------------------------------------- Python
_PY_ROUTER_PREFIX = re.compile(r"(?P<var>\w+)\s*=\s*(?:fastapi\.)?APIRouter\s*\((?P<args>[^)]*)\)")
_PY_BLUEPRINT = re.compile(r"(?P<var>\w+)\s*=\s*(?:flask\.)?Blueprint\s*\((?P<args>[^)]*)\)")
_PY_PREFIX_ARG = re.compile(r"(?:prefix|url_prefix)\s*=\s*['\"](?P<prefix>[^'\"]*)['\"]")
_PY_INCLUDE = re.compile(r"\.include_router\s*\(\s*(?P<var>[\w.]+)\s*(?P<args>[^)]*)\)")
_PY_FASTAPI = re.compile(r"@\s*(?P<var>\w+)\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['\"](?P<path>[^'\"]*)['\"]", re.I)
_PY_API_ROUTE = re.compile(r"@\s*(?P<var>\w+)\.api_route\s*\(\s*['\"](?P<path>[^'\"]*)['\"](?P<args>[^)]*)\)", re.I)
_PY_FLASK = re.compile(r"@\s*(?P<var>\w+)\.route\s*\(\s*['\"](?P<path>[^'\"]*)['\"](?P<args>[^)]*)\)", re.I)
_METHODS_LIST = re.compile(r"methods\s*=\s*[\[(](?P<methods>[^\])]*)[\])]", re.I)
_QUOTED_METHOD = re.compile(r"['\"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]", re.I)


def _python_routes(content: str, file: str) -> list[CodeRoute]:
    prefixes: dict[str, str] = {}
    for pattern in (_PY_ROUTER_PREFIX, _PY_BLUEPRINT):
        for match in pattern.finditer(content):
            arg = _PY_PREFIX_ARG.search(match["args"])
            prefixes[match["var"]] = arg["prefix"] if arg else ""
    for match in _PY_INCLUDE.finditer(content):
        arg = _PY_PREFIX_ARG.search(match["args"])
        var = match["var"].split(".")[-1]
        if arg and var in prefixes:
            prefixes[var] = arg["prefix"] + prefixes[var]
    routes = []
    for match in _PY_FASTAPI.finditer(content):
        routes.append(CodeRoute(match["method"].upper(), _join(prefixes.get(match["var"], ""), match["path"]), file, _line_of(content, match.start()), "fastapi"))
    for match in _PY_API_ROUTE.finditer(content):
        listed = _METHODS_LIST.search(match["args"])
        methods = [m.upper() for m in _QUOTED_METHOD.findall(listed["methods"])] if listed else ["GET"]
        for method in methods:
            routes.append(CodeRoute(method, _join(prefixes.get(match["var"], ""), match["path"]), file, _line_of(content, match.start()), "fastapi"))
    for match in _PY_FLASK.finditer(content):
        listed = _METHODS_LIST.search(match["args"])
        methods = [m.upper() for m in _QUOTED_METHOD.findall(listed["methods"])] if listed else ["GET"]
        for method in methods:
            routes.append(CodeRoute(method, _join(prefixes.get(match["var"], ""), match["path"]), file, _line_of(content, match.start()), "flask"))
    return routes


# ---------------------------------------------------------------- JavaScript / TypeScript (Express)
_JS_METHOD = re.compile(r"\b(?P<var>\w+)\s*\.\s*(?P<method>get|post|put|patch|delete|all|head|options)\s*\(\s*(?P<q>['\"`])(?P<path>/[^'\"`]*)(?P=q)", re.I)
_JS_ROUTE_CHAIN = re.compile(r"\b(?P<var>\w+)\s*\.\s*route\s*\(\s*(?P<q>['\"`])(?P<path>/[^'\"`]*)(?P=q)\s*\)(?P<chain>(?:\s*\.\s*(?:get|post|put|patch|delete|all)\s*\([^;]*?\))+)", re.I | re.S)
_JS_CHAIN_METHOD = re.compile(r"\.\s*(get|post|put|patch|delete|all)\s*\(", re.I)
_JS_USE_VAR = re.compile(r"\b\w+\s*\.\s*use\s*\(\s*(?P<q>['\"`])(?P<prefix>/[^'\"`]*)(?P=q)\s*,\s*(?P<target>[\w.]+|require\(\s*['\"](?P<req>[^'\"]+)['\"]\s*\))\s*[,)]")
_JS_REQUIRE_VAR = re.compile(r"(?:const|let|var)\s+(?P<var>\w+)\s*=\s*require\(\s*['\"](?P<req>[^'\"]+)['\"]\s*\)")
_JS_IMPORT_VAR = re.compile(r"import\s+(?P<var>\w+)\s+from\s+['\"](?P<req>[^'\"]+)['\"]")
_JS_ROUTER_VARS = re.compile(r"(?:const|let|var)\s+(?P<var>\w+)\s*=\s*(?:express\s*\.\s*Router|Router|express)\s*\(")


def _resolve_js(base: Path, request: str) -> str | None:
    if not request.startswith("."):
        return None
    target = (base.parent / request).resolve()
    for candidate in (target, target.with_suffix(".js"), target.with_suffix(".ts"), target / "index.js", target / "index.ts"):
        if candidate.suffix and candidate.exists() and candidate.is_file():
            return str(candidate)
    return str(target.with_suffix(".js"))


def _js_mounts(files: dict[str, str]) -> dict[str, str]:
    """Map resolved file -> mount prefix from app.use('/prefix', require('./file'))."""
    mounts: dict[str, str] = {}
    for file, content in files.items():
        base = Path(file)
        required = {m["var"]: m["req"] for m in _JS_REQUIRE_VAR.finditer(content)}
        required.update({m["var"]: m["req"] for m in _JS_IMPORT_VAR.finditer(content)})
        for match in _JS_USE_VAR.finditer(content):
            request = match["req"] or required.get(match["target"].split(".")[0])
            if request:
                resolved = _resolve_js(base, request)
                if resolved:
                    mounts[resolved] = match["prefix"]
    return mounts


def _js_routes(content: str, file: str, mount_prefix: str) -> list[CodeRoute]:
    routers = {m["var"] for m in _JS_ROUTER_VARS.finditer(content)} or {"app", "router"}
    local_prefix = {}
    for match in _JS_USE_VAR.finditer(content):
        target = match["target"]
        if target in routers:
            local_prefix[target] = match["prefix"]
    routes = []
    for match in _JS_METHOD.finditer(content):
        var = match["var"]
        if var not in routers and var not in {"app", "router", "api", "server"}:
            continue
        method = "GET" if match["method"].lower() == "all" else match["method"].upper()
        prefix = mount_prefix + local_prefix.get(var, "")
        routes.append(CodeRoute(method, _join(prefix, match["path"]), file, _line_of(content, match.start()), "express"))
    for match in _JS_ROUTE_CHAIN.finditer(content):
        prefix = mount_prefix + local_prefix.get(match["var"], "")
        for method in _JS_CHAIN_METHOD.findall(match["chain"]):
            method = "GET" if method.lower() == "all" else method.upper()
            routes.append(CodeRoute(method, _join(prefix, match["path"]), file, _line_of(content, match.start()), "express"))
    return routes


# ---------------------------------------------------------------- Java (Spring)
_JAVA_MAPPING = re.compile(r"@(?P<kind>Get|Post|Put|Patch|Delete|Request)Mapping\s*(?:\((?P<args>[^)]*)\))?", re.S)
_JAVA_PATH_ARGS = re.compile(r"(?:(?:value|path)\s*=\s*)?(?:\{(?P<arr>[^}]*)\}|\"(?P<one>[^\"]*)\")")
_JAVA_REQ_METHOD = re.compile(r"RequestMethod\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)")
_JAVA_CLASS = re.compile(r"\bclass\s+\w+")


def _java_paths(args: str | None) -> list[str]:
    if not args:
        return [""]
    cleaned = re.sub(r"(produces|consumes|headers|params)\s*=\s*(\{[^}]*\}|\"[^\"]*\"|[\w.]+)", "", args)
    match = _JAVA_PATH_ARGS.search(cleaned)
    if not match:
        return [""]
    if match["arr"] is not None:
        return re.findall(r"\"([^\"]*)\"", match["arr"]) or [""]
    return [match["one"]]


def _java_routes(content: str, file: str) -> list[CodeRoute]:
    class_match = _JAVA_CLASS.search(content)
    class_index = class_match.start() if class_match else 0
    base_paths = [""]
    routes = []
    for match in _JAVA_MAPPING.finditer(content):
        kind = match["kind"]
        if match.start() < class_index:
            if kind == "Request":
                base_paths = _java_paths(match["args"])
            continue
        if kind == "Request":
            methods = _JAVA_REQ_METHOD.findall(match["args"] or "") or ["GET"]
        else:
            methods = [kind.upper()]
        for base in base_paths:
            for path in _java_paths(match["args"]):
                for method in methods:
                    routes.append(CodeRoute(method, _join(base, path), file, _line_of(content, match.start()), "spring"))
    return routes


# ---------------------------------------------------------------- Go
_GO_SUBROUTER = re.compile(r"(?P<var>\w+)\s*:?=\s*(?P<parent>\w+)\.PathPrefix\(\s*\"(?P<prefix>[^\"]*)\"\s*\)\.Subrouter\(\)")
_GO_GROUP = re.compile(r"(?P<var>\w+)\s*:?=\s*(?P<parent>\w+)\.Group\(\s*\"(?P<prefix>[^\"]*)\"")
_GO_HANDLEFUNC = re.compile(r"(?P<var>\w+)\.Handle(?:Func)?\(\s*\"(?P<path>[^\"]+)\"(?P<rest>[^\n]*)")
_GO_METHODS_CALL = re.compile(r"\.Methods\((?P<methods>[^)]*)\)")
_GO_METHODS_PATH = re.compile(r"(?P<var>\w+)\.Methods\((?P<methods>[^)]*)\)\s*\.\s*(?P<kind>PathPrefix|Path)\(\s*\"(?P<path>[^\"]+)\"")
_GO_VERB = re.compile(r"(?P<var>\w+)\.(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Get|Post|Put|Patch|Delete|Head|Options)\(\s*\"(?P<path>/[^\"]*)\"")


def _go_routes(content: str, file: str) -> list[CodeRoute]:
    prefixes: dict[str, str] = {}
    for pattern in (_GO_SUBROUTER, _GO_GROUP):
        for match in pattern.finditer(content):
            prefixes[match["var"]] = prefixes.get(match["parent"], "") + match["prefix"]
    routes = []
    for match in _GO_METHODS_PATH.finditer(content):
        path = match["path"].rstrip("/") + "*" if match["kind"] == "PathPrefix" else match["path"]
        for method in re.findall(r"\"(\w+)\"", match["methods"]):
            routes.append(CodeRoute(method.upper(), _join(prefixes.get(match["var"], ""), path), file, _line_of(content, match.start()), "gorilla/mux",
                                    "prefix route (matches every path below it)" if match["kind"] == "PathPrefix" else ""))
    for match in _GO_HANDLEFUNC.finditer(content):
        raw = match["path"]
        explicit = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/.*)$", raw)
        listed = _GO_METHODS_CALL.search(match["rest"])
        prefix = prefixes.get(match["var"], "")
        if explicit:
            routes.append(CodeRoute(explicit.group(1), _join(prefix, explicit.group(2)), file, _line_of(content, match.start()), "net/http"))
        elif listed:
            for method in re.findall(r"\"(\w+)\"", listed["methods"]):
                routes.append(CodeRoute(method.upper(), _join(prefix, raw), file, _line_of(content, match.start()), "gorilla/mux"))
        elif raw.startswith("/"):
            routes.append(CodeRoute("GET", _join(prefix, raw), file, _line_of(content, match.start()), "net/http", "method-agnostic handler; assumed GET"))
    for match in _GO_VERB.finditer(content):
        routes.append(CodeRoute(match["method"].upper(), _join(prefixes.get(match["var"], ""), match["path"]), file, _line_of(content, match.start()), "gin/echo/chi"))
    return routes


# ---------------------------------------------------------------- entry points
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"(?m)^\s*(//|#).*$")


def strip_comments(content: str, suffix: str) -> str:
    """Blank out comments (keeping line numbers) so commented-out routes are not reported."""
    blank = lambda match: re.sub(r"[^\n]", " ", match.group(0))  # noqa: E731
    if suffix != ".py":
        content = _BLOCK_COMMENT.sub(blank, content)
    return _LINE_COMMENT.sub(blank, content)


def routes_from_content(content: str, file: str, mount_prefix: str = "") -> list[CodeRoute]:
    suffix = Path(file).suffix.lower()
    content = strip_comments(content, suffix)
    if suffix == ".py":
        return _python_routes(content, file)
    if suffix in {".js", ".mjs", ".cjs", ".ts"}:
        return _js_routes(content, file, mount_prefix)
    if suffix in {".java", ".kt"}:
        return _java_routes(content, file)
    if suffix == ".go":
        return _go_routes(content, file)
    return []


def routes_from_files(files: dict[str, str], root: Path | None = None) -> list[CodeRoute]:
    """Extract routes from {absolute_or_relative_path: content}, resolving Express mounts across files."""
    js_files = {f: c for f, c in files.items() if Path(f).suffix.lower() in {".js", ".mjs", ".cjs", ".ts"}}
    mounts = _js_mounts(js_files) if js_files else {}
    routes: list[CodeRoute] = []
    for file, content in files.items():
        resolved = str(Path(file).resolve()) if Path(file).is_absolute() or root else file
        mount = mounts.get(resolved, mounts.get(str(Path(file).resolve()), ""))
        display = str(Path(file).relative_to(root)) if root and Path(file).is_absolute() and Path(file).is_relative_to(root) else file
        for route in routes_from_content(content, file, mount):
            routes.append(CodeRoute(route.method, route.path, display.replace("\\", "/"), route.line, route.framework, route.note))
    unique: dict[tuple[str, str], CodeRoute] = {}
    for route in routes:
        unique.setdefault((route.method, route.path), route)
    return list(unique.values())


def read_source_tree(repository: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in repository.rglob("*"):
        if path.suffix.lower() not in SUFFIXES or not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(repository).parts[:-1]):
            continue
        try:
            files[str(path.resolve())] = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
    return files


def discover_repository(repository: Path) -> list[CodeRoute]:
    return routes_from_files(read_source_tree(repository), root=repository.resolve())
