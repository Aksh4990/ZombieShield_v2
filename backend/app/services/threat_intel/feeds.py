"""Vulnerability feeds: OSV.dev (online) with an offline OSV-format cache, CISA KEV and FIRST EPSS."""

import json
import logging
from functools import lru_cache
from pathlib import Path

import httpx

from app.core.config import get_settings
from app.services.threat_intel.cvss import base_score, severity_from_score
from app.services.threat_intel.versions import fixed_versions, is_affected

log = logging.getLogger(__name__)
_GHSA_SEVERITY = {"LOW": "LOW", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}


def _cache_dir() -> Path:
    path = Path(get_settings().threat_cache_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def package_key(ecosystem: str, name: str) -> str:
    name = name.lower().replace("_", "-") if ecosystem == "PyPI" else name
    return f"{ecosystem}:{name}"


@lru_cache(maxsize=1)
def _offline_index() -> dict:
    path = _cache_dir() / "osv_index.json"
    return json.loads(path.read_text()) if path.is_file() else {}


def offline_available() -> bool:
    return bool(_offline_index())


def summarise(record: dict) -> dict:
    """Normalise an OSV record into the fields ZombieShield stores."""
    vector, score = None, None
    for entry in record.get("severity") or []:
        if entry.get("type") == "CVSS_V3" and isinstance(entry.get("score"), str):
            vector = entry["score"]
            score = base_score(vector)
            break
    if vector is None:
        for entry in record.get("severity") or []:
            if isinstance(entry.get("score"), str):
                vector = entry["score"]
                break
    label = severity_from_score(score)
    if label == "UNKNOWN":
        label = _GHSA_SEVERITY.get(str((record.get("database_specific") or {}).get("severity", "")).upper(), "UNKNOWN")
    aliases = [alias for alias in record.get("aliases") or [] if isinstance(alias, str)]
    cve = next((alias for alias in aliases if alias.startswith("CVE-")), None)
    return {
        "id": record["id"], "aliases": aliases, "summary": (record.get("summary") or record.get("details") or "")[:1900],
        "severity": label, "cvss_score": score, "cvss_vector": vector, "published": record.get("published"),
        "references": [ref.get("url") for ref in record.get("references") or [] if ref.get("url")][:8],
        "url": f"https://osv.dev/vulnerability/{record['id']}", "cve": cve,
    }


def _match(record: dict, ecosystem: str, name: str, version: str) -> list[str] | None:
    key = package_key(ecosystem, name)
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        if package_key(package.get("ecosystem", ""), package.get("name", "")) != key:
            continue
        if is_affected(ecosystem, version, affected):
            return fixed_versions(affected)
    return None


def query_offline(ecosystem: str, name: str, version: str) -> list[tuple[dict, list[str]]]:
    out = []
    for record in _offline_index().get(package_key(ecosystem, name), []):
        if record.get("withdrawn"):
            continue
        fixed = _match(record, ecosystem, name, version)
        if fixed is not None:
            out.append((record, fixed))
    return out


def query_online(packages: list[tuple[str, str, str]]) -> list[list[tuple[dict, list[str]]]]:
    """Batch query OSV.dev, then fetch full records (cached on disk)."""
    settings = get_settings()
    queries = [{"package": {"ecosystem": eco, "name": name}, "version": version} for eco, name, version in packages]
    results: list[list[tuple[dict, list[str]]]] = []
    with httpx.Client(timeout=20) as client:
        response = client.post(f"{settings.osv_api_url}/querybatch", json={"queries": queries})
        response.raise_for_status()
        vuln_dir = _cache_dir() / "vulns"
        vuln_dir.mkdir(exist_ok=True)
        for (eco, name, version), result in zip(packages, response.json().get("results", [])):
            matches = []
            for item in result.get("vulns") or []:
                cached = vuln_dir / f"{item['id']}.json"
                if cached.is_file():
                    record = json.loads(cached.read_text())
                else:
                    detail = client.get(f"{settings.osv_api_url}/vulns/{item['id']}")
                    if detail.status_code != 200:
                        continue
                    record = detail.json()
                    cached.write_text(json.dumps(record))
                fixed = _match(record, eco, name, version)
                matches.append((record, fixed or []))
            results.append(matches)
    return results


@lru_cache(maxsize=1)
def kev_catalogue() -> dict[str, dict]:
    """CVE -> KEV entry. Online feed is cached to disk; the cached copy is used offline."""
    settings = get_settings()
    path = _cache_dir() / "kev.json"
    if settings.threat_intel_mode != "offline":
        try:
            response = httpx.get(settings.kev_feed_url, timeout=20)
            response.raise_for_status()
            path.write_text(response.text)
        except httpx.HTTPError as exc:
            log.info("KEV feed unavailable (%s); using cached copy", exc)
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    return {item["cveID"]: item for item in data.get("vulnerabilities", [])}


def epss_scores(cves: list[str]) -> dict[str, tuple[float, float]]:
    settings = get_settings()
    path = _cache_dir() / "epss.json"
    cache = json.loads(path.read_text()) if path.is_file() else {}
    missing = [cve for cve in cves if cve not in cache]
    if missing and settings.threat_intel_mode != "offline":
        try:
            for start in range(0, len(missing), 80):
                chunk = missing[start:start + 80]
                response = httpx.get(settings.epss_api_url, params={"cve": ",".join(chunk)}, timeout=20)
                response.raise_for_status()
                for row in response.json().get("data", []):
                    cache[row["cve"]] = [float(row["epss"]), float(row["percentile"])]
            path.write_text(json.dumps(cache))
        except httpx.HTTPError as exc:
            log.info("EPSS API unavailable (%s)", exc)
    return {cve: tuple(cache[cve]) for cve in cves if cve in cache}
