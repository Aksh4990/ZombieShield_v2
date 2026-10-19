"""Git history mining: when did each route / documented operation appear and disappear?

A route that existed in an earlier commit but is absent at HEAD is the strongest
static evidence that an endpoint was *retired*. If runtime traffic still reaches
it, the endpoint is a zombie in the strict sense.
"""

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from app.services.discovery.code_routes import SKIP_DIRS, SUFFIXES, routes_from_files
from app.services.discovery.openapi import SpecError, parse_spec
from app.services.normalization import normalize_path

SPEC_PREFIXES = ("openapi", "swagger")
SPEC_SUFFIXES = (".yaml", ".yml", ".json")


@dataclass
class Commit:
    sha: str
    author: str
    date: str
    subject: str
    parent: str = ""


@dataclass
class PresenceHistory:
    method: str
    path: str
    display_path: str
    file: str
    first_commit: Commit
    last_commit: Commit
    removed_commit: Commit | None = None
    present_at_head: bool = True


@dataclass
class HistoryResult:
    commits: list[Commit] = field(default_factory=list)
    routes: dict[tuple[str, str], PresenceHistory] = field(default_factory=dict)
    spec_operations: dict[tuple[str, str], PresenceHistory] = field(default_factory=dict)

    @property
    def removed_routes(self) -> list[PresenceHistory]:
        return [item for item in self.routes.values() if not item.present_at_head]

    @property
    def removed_spec_operations(self) -> list[PresenceHistory]:
        return [item for item in self.spec_operations.values() if not item.present_at_head]


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(repo), *args],
        capture_output=True, text=True, timeout=60, check=False, encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def is_git_repository(repo: Path) -> bool:
    try:
        return _git(repo, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except (RuntimeError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _commits(repo: Path, max_commits: int) -> list[Commit]:
    output = _git(repo, "log", f"-n{max_commits}", "--format=%H%x1f%an%x1f%aI%x1f%s%x1f%P", "--first-parent")
    commits = []
    for line in output.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 5:
            commits.append(Commit(parts[0], parts[1], parts[2], parts[3], parts[4].split(" ")[0] if parts[4] else ""))
    return list(reversed(commits))


def _changes(repo: Path, commit: "Commit", previous: str | None) -> list[tuple[str, str]]:
    """Files changed since the previously processed commit (first-parent chain, merges included)."""
    if previous:
        output = _git(repo, "diff", "--name-status", "--no-renames", previous, commit.sha)
    else:
        output = _git(repo, "ls-tree", "-r", "--name-only", commit.sha)
        return [("A", line) for line in output.splitlines() if line]
    changes = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            changes.append((parts[0][0], parts[-1]))
    return changes


def _tracked(path: str) -> bool:
    parts = Path(path).parts
    return not any(part in SKIP_DIRS for part in parts[:-1])


def _is_code(path: str) -> bool:
    return Path(path).suffix.lower() in SUFFIXES and _tracked(path)


SPEC_DIRS = {"api-spec", "apispec", "openapi", "swagger", "api-docs"}


def _is_spec(path: str) -> bool:
    file = Path(path)
    name = file.name.lower()
    if not name.endswith(SPEC_SUFFIXES) or not _tracked(path) or name in {"package.json", "package-lock.json", "tsconfig.json"}:
        return False
    return name.startswith(SPEC_PREFIXES) or any(part.lower() in SPEC_DIRS for part in file.parts[:-1])


def _update_presence(store: dict, current: dict[tuple[str, str], tuple[str, str]], commit: Commit) -> None:
    for key, (display, file) in current.items():
        if key not in store:
            store[key] = PresenceHistory(key[0], key[1], display, file, first_commit=commit, last_commit=commit)
        else:
            store[key].last_commit = commit
            store[key].removed_commit = None


def mine_history(repo: Path, max_commits: int = 300) -> HistoryResult:
    repo = repo.resolve()
    result = HistoryResult(commits=_commits(repo, max_commits))
    code_files: dict[str, str] = {}
    spec_files: dict[str, str] = {}
    previous_routes: set = set()
    previous_spec: set = set()
    previous_sha: str | None = None
    for commit in result.commits:
        code_changed = spec_changed = False
        changes = _changes(repo, commit, previous_sha)
        previous_sha = commit.sha
        for status, path in changes:
            target = None
            if _is_code(path):
                target, code_changed = code_files, True
            elif _is_spec(path):
                target, spec_changed = spec_files, True
            if target is None:
                continue
            if status == "D":
                target.pop(str(repo / path), None)
            else:
                try:
                    target[str(repo / path)] = _git(repo, "show", f"{commit.sha}:{path}")
                except RuntimeError:
                    target.pop(str(repo / path), None)

        if code_changed or not result.routes:
            routes = routes_from_files(code_files, root=repo)
            current = {(r.method, normalize_path(r.path)): (r.path, r.file) for r in routes}
            for key in previous_routes - set(current):
                if key in result.routes and result.routes[key].removed_commit is None:
                    result.routes[key].removed_commit = commit
            _update_presence(result.routes, current, commit)
            previous_routes = set(current)
        else:
            _update_presence(result.routes, {k: (result.routes[k].display_path, result.routes[k].file) for k in previous_routes}, commit)

        if spec_changed or not result.spec_operations:
            current_spec: dict[tuple[str, str], tuple[str, str]] = {}
            for file, content in spec_files.items():
                try:
                    parsed = parse_spec(content)
                except SpecError:
                    continue
                relative = str(Path(file).relative_to(repo)).replace("\\", "/")
                for operation in parsed.operations:
                    current_spec[(operation.method, normalize_path(operation.path))] = (operation.path, relative)
            for key in previous_spec - set(current_spec):
                if key in result.spec_operations and result.spec_operations[key].removed_commit is None:
                    result.spec_operations[key].removed_commit = commit
            _update_presence(result.spec_operations, current_spec, commit)
            previous_spec = set(current_spec)
        else:
            _update_presence(result.spec_operations, {k: (result.spec_operations[k].display_path, result.spec_operations[k].file) for k in previous_spec}, commit)

    for key, item in result.routes.items():
        item.present_at_head = key in previous_routes
    for key, item in result.spec_operations.items():
        item.present_at_head = key in previous_spec
    return result
