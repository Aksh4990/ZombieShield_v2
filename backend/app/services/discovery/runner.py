"""Run configured discovery sources (OpenAPI, Git + history, runtime logs) into the inventory."""

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Source
from app.services import traffic
from app.services.discovery.code_routes import discover_repository
from app.services.discovery.git_history import _is_spec, is_git_repository, mine_history
from app.services.discovery.openapi import SpecError, parse_spec
from app.services.inventory import InventoryWriter, Observation


class DiscoveryError(ValueError):
    pass


@dataclass
class SourceRunResult:
    source: str
    kind: str
    discovered: int = 0
    added: int = 0
    retired: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"source": self.source, "kind": self.kind, "discovered": self.discovered, "added": self.added, "retired": self.retired, "notes": self.notes}


def resolve_repository(location: str) -> Path:
    root = Path(get_settings().discovery_git_root).resolve()
    requested = Path(location)
    if requested.is_absolute() or ".." in requested.parts:
        raise DiscoveryError("Repository path must be relative to the configured discovery root")
    repository = (root / requested).resolve()
    if not repository.is_relative_to(root):
        raise DiscoveryError("Repository path escapes the configured discovery root")
    if not repository.is_dir():
        raise DiscoveryError(f"Repository '{location}' does not exist under the discovery root")
    return repository


def _load_spec_text(source: Source) -> str:
    location = source.location
    if location.startswith(("http://", "https://")):
        headers = {}
        header_env = (source.options or {}).get("auth_header_env")
        if header_env and os.environ.get(header_env):
            headers["Authorization"] = os.environ[header_env]
        response = httpx.get(location, headers=headers, timeout=15)
        response.raise_for_status()
        return response.text
    path = Path(location)
    if not path.is_absolute():
        path = resolve_repository(location) if path.is_dir() else (Path(get_settings().discovery_git_root).resolve() / location)
    if not path.is_file():
        raise DiscoveryError(f"Specification file '{location}' was not found")
    return path.read_text(encoding="utf-8")


def ingest_spec_text(db: Session, writer: InventoryWriter, text: str, *, name: str, organization: str, host: str | None, service_name: str | None) -> SourceRunResult:
    try:
        spec = parse_spec(text)
    except SpecError as exc:
        raise DiscoveryError(str(exc)) from exc
    result = SourceRunResult(name, "openapi")
    seen = set()
    before = writer.added
    for operation in spec.operations:
        api = writer.observe(Observation(
            organization=organization, host=host or spec.host or "api.local", service_name=service_name or spec.title,
            method=operation.method, path=operation.path, source_kind="openapi", source_name=name,
            observed_at=datetime.now(timezone.utc), spec=operation, spec_version=spec.version,
        ))
        seen.add(api.id)
    result.discovered = len(spec.operations)
    result.added = writer.added - before
    result.retired = writer.finish_source("openapi", name, seen)
    deprecated = sum(1 for op in spec.operations if op.deprecated)
    label = spec.version if spec.version not in ("", "unversioned") else "unversioned"
    result.notes.append(f"{spec.format} '{spec.title}' ({label}): {len(spec.operations)} operations, {deprecated} marked deprecated")
    return result


def run_openapi_source(db: Session, writer: InventoryWriter, source: Source) -> SourceRunResult:
    return ingest_spec_text(db, writer, _load_spec_text(source), name=source.name, organization=source.organization, host=source.host, service_name=source.service_name)


def run_git_source(db: Session, writer: InventoryWriter, source: Source) -> list[SourceRunResult]:
    repository = resolve_repository(source.location)
    service = source.service_name or repository.name
    results = []
    code_result = SourceRunResult(source.name, "git")
    seen = set()
    before = writer.added
    routes = discover_repository(repository)
    for route in routes:
        api = writer.observe(Observation(
            organization=source.organization, host=source.host, service_name=service, method=route.method, path=route.path,
            source_kind="git", source_name=source.name, observed_at=datetime.now(timezone.utc), code=route,
        ))
        seen.add(api.id)
    code_result.discovered = len(routes)
    code_result.added = writer.added - before
    code_result.retired = writer.finish_source("git", source.name, seen)
    frameworks = sorted({route.framework for route in routes})
    code_result.notes.append(f"{len(routes)} routes at HEAD ({', '.join(frameworks) or 'no supported framework found'})")
    results.append(code_result)

    # Specifications committed inside the repository are treated as documentation evidence.
    spec_files = (source.options or {}).get("spec_files") or find_spec_files(repository)
    for spec_rel in spec_files:
        spec_path = (repository / spec_rel).resolve()
        if spec_path.is_relative_to(repository) and spec_path.is_file():
            try:
                results.append(ingest_spec_text(db, writer, spec_path.read_text(encoding="utf-8"), name=f"{source.name}:{spec_rel}",
                                                organization=source.organization, host=source.host, service_name=service))
            except DiscoveryError as exc:
                code_result.notes.append(f"Skipped {spec_rel}: {exc}")

    if (source.options or {}).get("mine_history", True) and is_git_repository(repository):
        results.append(apply_history(writer, source, repository, service))
    return results


def find_spec_files(repository: Path) -> list[str]:
    """Specification documents committed in the repository (openapi*/swagger* files, api-spec/ folders)."""
    found = []
    for path in sorted(repository.rglob("*")):
        relative = str(path.relative_to(repository)).replace("\\", "/")
        if path.is_file() and _is_spec(relative):
            try:
                parse_spec(path.read_text(encoding="utf-8"))
            except (SpecError, UnicodeDecodeError, OSError):
                continue
            found.append(relative)
    return found


def apply_history(writer: InventoryWriter, source: Source, repository: Path, service: str) -> SourceRunResult:
    history = mine_history(repository)
    result = SourceRunResult(f"{source.name} (history)", "git_history")
    for item in history.routes.values():
        api, _ = writer.get_or_create(source.organization, source.host, service, item.method, item.path, _date(item.first_commit.date))
        writer.add_evidence(api, "introduced_in_git", source.name,
                            f"Route introduced in commit {item.first_commit.sha[:8]} by {item.first_commit.author}: \"{item.first_commit.subject}\"",
                            {"commit": item.first_commit.sha, "file": item.file}, _date(item.first_commit.date), dedupe_key=f"git-intro:{source.name}")
        if not item.present_at_head and item.removed_commit:
            removed = item.removed_commit
            api.previously_in_code = True
            api.removed_in_commit = removed.sha
            api.removed_at = _date(removed.date)
            api.removal_note = f"Removed from source in commit {removed.sha[:8]} by {removed.author} on {removed.date[:10]}: \"{removed.subject}\""
            tag = f"git:{source.name}"
            if tag not in (api.sources or []):
                api.sources = [*(api.sources or []), tag]
            writer.add_evidence(api, "removed_in_git", source.name, api.removal_note,
                                {"commit": removed.sha, "author": removed.author, "file": item.file}, _date(removed.date), dedupe_key=f"git-removed:{source.name}:{removed.sha}")
            writer.refresh_flags(api)
            result.retired += 1
    for item in history.spec_operations.values():
        if item.present_at_head or not item.removed_commit:
            continue
        api, _ = writer.get_or_create(source.organization, source.host, service, item.method, item.path, _date(item.first_commit.date))
        removed = item.removed_commit
        api.previously_in_spec = True
        if not api.removal_note:
            api.removed_at = _date(removed.date)
            api.removed_in_commit = removed.sha
            api.removal_note = f"Removed from the published specification in commit {removed.sha[:8]} on {removed.date[:10]}: \"{removed.subject}\""
        tag = f"openapi:{source.name}:{item.file}"
        if tag not in (api.sources or []):
            api.sources = [*(api.sources or []), tag]
        writer.add_evidence(api, "removed_from_spec_history", source.name,
                            f"Operation dropped from {item.file} in commit {removed.sha[:8]}: \"{removed.subject}\"",
                            {"commit": removed.sha, "file": item.file}, _date(removed.date), dedupe_key=f"spec-removed:{source.name}:{removed.sha}")
        writer.refresh_flags(api)
        result.retired += 1
    result.discovered = len(history.routes)
    result.notes.append(f"{len(history.commits)} commits mined; {len(history.removed_routes)} routes and {len(history.removed_spec_operations)} documented operations were retired")
    return result


def _date(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def run_log_source(db: Session, writer: InventoryWriter, source: Source, *, from_start: bool = False) -> SourceRunResult:
    path = Path(source.location)
    result = SourceRunResult(source.name, "runtime_log")
    if not path.is_file():
        result.notes.append(f"Log file {source.location} not found yet")
        return result
    options = dict(source.options or {})
    offset = 0 if from_start else int(options.get("offset", 0))
    size = path.stat().st_size
    if size < offset:  # rotated / truncated
        offset = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        content = handle.read()
        new_offset = handle.tell()
    if content and not content.endswith("\n"):
        cut = content.rfind("\n") + 1
        new_offset = offset + len(content[:cut].encode("utf-8"))
        content = content[:cut]
    stats = traffic.ingest_log_content(db, writer, content, source_name=source.name, organization=source.organization,
                                       host=source.host, default_service=source.service_name or "runtime-service")
    options["offset"] = new_offset
    source.options = options
    result.discovered = stats["records"]
    result.added = stats["new_apis"]
    result.notes.append(f"{stats['records']} requests ingested ({stats['skipped']} unparseable lines, {stats['attacks']} flagged by the payload classifier, {stats['ignored_404']} 404 probes kept out of the inventory)")
    return result


def run_source(db: Session, source: Source, writer: InventoryWriter | None = None, **kwargs) -> list[SourceRunResult]:
    own_writer = writer is None
    writer = writer or InventoryWriter(db)
    try:
        if source.kind == "openapi":
            results = [run_openapi_source(db, writer, source)]
        elif source.kind == "git":
            results = run_git_source(db, writer, source)
        elif source.kind == "runtime_log":
            results = [run_log_source(db, writer, source, **kwargs)]
        else:
            results = []
        source.last_status = "; ".join(note for r in results for note in r.notes) or "ok"
    except (DiscoveryError, httpx.HTTPError, OSError, RuntimeError) as exc:
        source.last_status = f"ERROR: {exc}"
        results = [SourceRunResult(source.name, source.kind, notes=[f"ERROR: {exc}"])]
    source.last_run_at = datetime.now(timezone.utc)
    if own_writer:
        writer.commit()
    return results
