"""Dependency extraction (a lightweight SBOM) from manifests and CycloneDX documents."""

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", "target", "vendor"}
_REQ = re.compile(r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*(?P<version>[A-Za-z0-9.+!_-]+)")
_GO_REQ = re.compile(r"^\s*(?P<name>[\w./-]+\.[\w./-]+)\s+(?P<version>v[\w.+-]+)")


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    manifest: str
    direct: bool = True

    @property
    def purl(self) -> str:
        kind = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "Maven": "maven"}.get(self.ecosystem, self.ecosystem.lower())
        name = self.name.replace(":", "/") if self.ecosystem == "Maven" else self.name
        return f"pkg:{kind}/{name}@{self.version}"


def _requirements(path: Path, rel: str) -> list[Dependency]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _REQ.match(line.split("#", 1)[0])
        if match:
            out.append(Dependency("PyPI", match["name"].lower().replace("_", "-"), match["version"], rel))
    return out


def _package_lock(path: Path, rel: str) -> list[Dependency]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        root = packages.get("", {})
        direct = set((root.get("dependencies") or {}).keys())
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict) or meta.get("dev") or not meta.get("version"):
                continue
            name = meta.get("name") or key.split("node_modules/")[-1]
            out.append(Dependency("npm", name, meta["version"], rel, name in direct))
    else:
        for name, meta in (data.get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("version") and not meta.get("dev"):
                out.append(Dependency("npm", name, meta["version"], rel))
    return out


def _package_json(path: Path, rel: str) -> list[Dependency]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for name, spec in (data.get("dependencies") or {}).items():
        version = re.sub(r"^[\^~>=<\s]+", "", str(spec)).split(" ")[0]
        if re.match(r"^\d", version):
            out.append(Dependency("npm", name, version, rel))
    return out


def _go_mod(path: Path, rel: str) -> list[Dependency]:
    out, in_block = [], False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require ") and not stripped.endswith("("):
            stripped = stripped[len("require "):]
        elif not in_block:
            continue
        match = _GO_REQ.match(stripped)
        if match:
            out.append(Dependency("Go", match["name"], match["version"], rel, "// indirect" not in stripped))
    return out


def _pom(path: Path, rel: str) -> list[Dependency]:
    tree = ET.parse(path)
    root = tree.getroot()
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    prefix = "m:" if ns else ""
    properties = {}
    props = root.find(f"{prefix}properties", ns)
    if props is not None:
        for child in props:
            properties[child.tag.split("}")[-1]] = (child.text or "").strip()
    parent_version = root.findtext(f"{prefix}parent/{prefix}version", default="", namespaces=ns)
    out = []
    for dep in root.findall(f".//{prefix}dependencies/{prefix}dependency", ns):
        group = dep.findtext(f"{prefix}groupId", default="", namespaces=ns)
        artifact = dep.findtext(f"{prefix}artifactId", default="", namespaces=ns)
        version = dep.findtext(f"{prefix}version", default="", namespaces=ns)
        scope = dep.findtext(f"{prefix}scope", default="", namespaces=ns)
        version = re.sub(r"\$\{([^}]+)\}", lambda m: properties.get(m.group(1), parent_version if m.group(1) == "project.version" else ""), version)
        if group and artifact and version and scope != "test":
            out.append(Dependency("Maven", f"{group}:{artifact}", version, rel))
    return out


def _cyclonedx(path: Path, rel: str) -> list[Dependency]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    mapping = {"pypi": "PyPI", "npm": "npm", "golang": "Go", "maven": "Maven"}
    for component in data.get("components") or []:
        purl = component.get("purl") or ""
        match = re.match(r"pkg:(\w+)/(.+)@([^?#]+)", purl)
        if not match or match.group(1) not in mapping:
            continue
        ecosystem = mapping[match.group(1)]
        name = match.group(2).replace("%40", "@")
        if ecosystem == "Maven":
            name = name.replace("/", ":")
        out.append(Dependency(ecosystem, name, match.group(3), rel))
    return out


def scan_directory(directory: Path) -> list[Dependency]:
    """Find manifests under a repository; package-lock.json wins over package.json in the same folder."""
    deps: list[Dependency] = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(directory).parts[:-1]):
            continue
        rel = str(path.relative_to(directory)).replace("\\", "/")
        name = path.name.lower()
        try:
            if name.startswith("requirements") and name.endswith(".txt"):
                deps.extend(_requirements(path, rel))
            elif name == "package-lock.json":
                deps.extend(_package_lock(path, rel))
            elif name == "package.json" and not (path.parent / "package-lock.json").exists():
                deps.extend(_package_json(path, rel))
            elif name == "go.mod":
                deps.extend(_go_mod(path, rel))
            elif name == "pom.xml":
                deps.extend(_pom(path, rel))
            elif name.endswith(".cdx.json") or name in {"bom.json", "sbom.json"}:
                deps.extend(_cyclonedx(path, rel))
        except (ValueError, ET.ParseError, OSError, json.JSONDecodeError):
            continue
    unique = {}
    for dep in deps:
        unique.setdefault((dep.ecosystem, dep.name, dep.version), dep)
    return list(unique.values())
