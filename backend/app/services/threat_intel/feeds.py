"""Vulnerability feeds: OSV.dev (online) with an offline OSV-format cache, CISA KEV and FIRST EPSS."""

import json
import logging
import time
from functools import lru_cache
from pathlib import Path

import httpx

from app.core.config import get_settings
from app.services.threat_intel.cvss import base_score, severity_from_score
from app.services.threat_intel.versions import fixed_versions, is_affected

log = logging.getLogger(__name__)
_GHSA_SEVERITY = {"LOW": "LOW", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}


def deadline(seconds: float | None = None) -> float:
    """A time.monotonic() deadline for online feed calls (default: the configured stage budget)."""
    return time.monotonic() + (get_settings().threat_intel_timeout_seconds if seconds is None else seconds)


def fetch(client: httpx.Client, method: str, url: str, until: float, **kwargs) -> httpx.Response:
    """One HTTP request that can never outlive `until`.

    httpx's timeout only bounds each connect/read *gap*, so a server that trickles bytes (the CISA
    feed does this to some clients) can hold a request open indefinitely. Streaming and checking the
    clock between chunks turns that into a TimeoutException, which callers treat as "feed unavailable".
    """
    remaining = until - time.monotonic()
    if remaining <= 0:
        raise httpx.TimeoutException(f"threat-intel time budget exhausted before {method} {url}")
    timeout = httpx.Timeout(min(15.0, remaining), connect=min(5.0, remaining))
    with client.stream(method, url, timeout=timeout, **kwargs) as response:
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if time.monotonic() > until:
                raise httpx.ReadTimeout(f"threat-intel time budget exhausted while downloading {url}", request=response.request)
        return httpx.Response(response.status_code, headers=response.headers, content=bytes(body), request=response.request)


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


def query_online(packages: list[tuple[str, str, str]], until: float | None = None) -> list[list[tuple[dict, list[str]]]]:
    """Batch query OSV.dev, then fetch full records (cached on disk). Raises httpx errors on timeout."""
    settings = get_settings()
    until = deadline() if until is None else until
    queries = [{"package": {"ecosystem": eco, "name": name}, "version": version} for eco, name, version in packages]
    results: list[list[tuple[dict, list[str]]]] = []
    with httpx.Client() as client:
        response = fetch(client, "POST", f"{settings.osv_api_url}/querybatch", until, json={"queries": queries})
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
                    detail = fetch(client, "GET", f"{settings.osv_api_url}/vulns/{item['id']}", until)
                    if detail.status_code != 200:
                        continue
                    record = detail.json()
                    cached.write_text(json.dumps(record))
                fixed = _match(record, eco, name, version)
                matches.append((record, fixed or []))
            results.append(matches)
    return results


@lru_cache(maxsize=1)
def kev_catalogue(until: float | None = None) -> dict[str, dict]:
    """CVE -> KEV entry. Online feed is cached to disk; the cached copy is used offline or on timeout."""
    settings = get_settings()
    path = _cache_dir() / "kev.json"
    if settings.threat_intel_mode != "offline":
        try:
            with httpx.Client() as client:
                response = fetch(client, "GET", settings.kev_feed_url, deadline() if until is None else until)
            response.raise_for_status()
            path.write_text(response.text)
        except httpx.HTTPError as exc:
            log.info("KEV feed unavailable (%s); using cached copy", exc)
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    return {item["cveID"]: item for item in data.get("vulnerabilities", [])}


def epss_scores(cves: list[str], until: float | None = None) -> dict[str, tuple[float, float]]:
    settings = get_settings()
    until = deadline() if until is None else until
    path = _cache_dir() / "epss.json"
    cache = json.loads(path.read_text()) if path.is_file() else {}
    missing = [cve for cve in cves if cve not in cache]
    if missing and settings.threat_intel_mode != "offline":
        try:
            with httpx.Client() as client:
                for start in range(0, len(missing), 80):
                    chunk = missing[start:start + 80]
                    response = fetch(client, "GET", settings.epss_api_url, until, params={"cve": ",".join(chunk)})
                    response.raise_for_status()
                    for row in response.json().get("data", []):
                        cache[row["cve"]] = [float(row["epss"]), float(row["percentile"])]
        except httpx.HTTPError as exc:
            log.info("EPSS API unavailable (%s); using cached scores", exc)
        path.write_text(json.dumps(cache))  # keep whatever was fetched before a timeout
    return {cve: tuple(cache[cve]) for cve in cves if cve in cache}
