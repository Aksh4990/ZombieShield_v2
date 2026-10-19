"""Threat-intelligence stage: SBOM -> OSV vulnerabilities -> KEV / EPSS enrichment -> per-API counts."""

import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import API, Component, Source, ThreatFinding, Vulnerability
from app.services.discovery.runner import DiscoveryError, resolve_repository
from app.services.threat_intel import feeds
from app.services.threat_intel.sbom import Dependency, scan_directory

log = logging.getLogger(__name__)


def collect_components(db: Session) -> list[Component]:
    """Scan every enabled git source (and any SBOM sources) for dependency manifests."""
    components: dict[tuple, Component] = {}
    existing = {(c.service_name, c.ecosystem, c.name, c.version): c for c in db.scalars(select(Component))}
    for source in db.scalars(select(Source).where(Source.enabled.is_(True), Source.kind.in_(["git", "sbom"]))):
        try:
            directory = resolve_repository(source.location) if source.kind == "git" else Path(source.location)
        except DiscoveryError as exc:
            log.warning("SBOM scan skipped for %s: %s", source.name, exc)
            continue
        service = source.service_name or Path(source.location).name
        dependencies: list[Dependency] = scan_directory(directory) if directory.is_dir() else []
        for dep in dependencies:
            key = (service, dep.ecosystem, dep.name, dep.version)
            component = existing.get(key) or Component(service_name=service, ecosystem=dep.ecosystem, name=dep.name, version=dep.version,
                                                       purl=dep.purl, manifest=dep.manifest, direct=dep.direct)
            if key not in existing:
                db.add(component)
            components[key] = component
    for key, component in existing.items():
        if key not in components:
            db.delete(component)
    db.flush()
    return list(components.values())


def correlate(db: Session) -> dict:
    settings = get_settings()
    components = collect_components(db)
    packages = [(c.ecosystem, c.name, c.version) for c in components]
    mode = settings.threat_intel_mode
    until = feeds.deadline()
    used = "offline cache"
    results: list[list[tuple[dict, list[str]]]] = []
    if packages and mode in {"online", "auto"}:
        try:
            results = feeds.query_online(packages, until)
            used = "OSV.dev API"
        except httpx.HTTPError as exc:
            if mode == "online":
                raise
            log.warning("OSV.dev unavailable or too slow (%s); falling back to offline cache", exc)
            results = []
            if mode == "auto":
                until = feeds.deadline(min(30.0, settings.threat_intel_timeout_seconds))  # small budget left for KEV / EPSS
    if not results:
        results = [feeds.query_offline(*package) for package in packages]
        used = "offline OSV cache (GitHub Advisory Database export)" if feeds.offline_available() else "none (no feed reachable and no offline cache)"

    db.execute(delete(ThreatFinding))
    kev = feeds.kev_catalogue(until)
    vulnerabilities: dict[str, Vulnerability] = {v.id: v for v in db.scalars(select(Vulnerability))}
    finding_count = 0
    for component, matches in zip(components, results):
        for record, fixed in matches:
            info = feeds.summarise(record)
            vuln = vulnerabilities.get(info["id"])
            if vuln is None:
                vuln = Vulnerability(id=info["id"])
                db.add(vuln)
                db.flush([vuln])  # the finding below references it; no ORM relationship orders the inserts
                vulnerabilities[info["id"]] = vuln
            vuln.aliases, vuln.summary, vuln.severity = info["aliases"], info["summary"], info["severity"]
            vuln.cvss_score, vuln.cvss_vector, vuln.references, vuln.url = info["cvss_score"], info["cvss_vector"], info["references"], info["url"]
            vuln.source = "OSV.dev / GitHub Advisory Database"
            if info["published"]:
                try:
                    vuln.published = datetime.fromisoformat(info["published"].replace("Z", "+00:00"))
                except ValueError:
                    pass
            cve = info["cve"]
            vuln.in_kev = bool(cve and cve in kev)
            vuln.kev_date_added = kev[cve]["dateAdded"] if vuln.in_kev else None
            vuln.updated_at = datetime.now(timezone.utc)
            db.add(ThreatFinding(component_id=component.id, vulnerability_id=vuln.id, service_name=component.service_name, fixed_versions=fixed,
                                 match_reason=f"{component.name} {component.version} ({component.ecosystem}) falls inside an affected range of {vuln.id}"
                                              + (f"; fixed in {', '.join(fixed)}" if fixed else "; no fixed version published")))
            finding_count += 1
    db.flush()
    cves = sorted({alias for v in vulnerabilities.values() for alias in v.aliases if alias.startswith("CVE-")})
    scores = feeds.epss_scores(cves, until) if cves else {}
    for vuln in vulnerabilities.values():
        cve = next((a for a in vuln.aliases if a.startswith("CVE-")), None)
        if cve in scores:
            vuln.epss, vuln.epss_percentile = scores[cve]

    # Roll up to APIs by service
    per_service: dict[str, list[Vulnerability]] = defaultdict(list)
    for finding in db.scalars(select(ThreatFinding)):
        per_service[finding.service_name].append(vulnerabilities[finding.vulnerability_id])
    for api in db.scalars(select(API)):
        vulns = per_service.get(api.service_name, [])
        api.vulnerability_count = len({v.id for v in vulns})
        api.kev_count = len({v.id for v in vulns if v.in_kev})
    return {"components": len(components), "findings": finding_count, "vulnerabilities": len({record["id"] for matches in results for record, _ in matches}),
            "kev_matches": sum(1 for v in vulnerabilities.values() if v.in_kev), "feed": used, "epss_scored": len(scores)}


def service_vulnerabilities(db: Session, service_name: str) -> list[dict]:
    rows = db.execute(
        select(ThreatFinding, Component, Vulnerability)
        .join(Component, ThreatFinding.component_id == Component.id)
        .join(Vulnerability, ThreatFinding.vulnerability_id == Vulnerability.id)
        .where(ThreatFinding.service_name == service_name)
    ).all()
    out = []
    for finding, component, vuln in rows:
        out.append({
            "id": vuln.id, "aliases": vuln.aliases, "summary": vuln.summary, "severity": vuln.severity, "cvss_score": vuln.cvss_score,
            "in_kev": vuln.in_kev, "kev_date_added": vuln.kev_date_added, "epss": vuln.epss, "epss_percentile": vuln.epss_percentile,
            "url": vuln.url, "component": component.name, "version": component.version, "ecosystem": component.ecosystem,
            "manifest": component.manifest, "fixed_versions": finding.fixed_versions, "match_reason": finding.match_reason,
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "NONE": 5}
    out.sort(key=lambda item: (not item["in_kev"], order.get(item["severity"], 9), -(item["cvss_score"] or 0)))
    return out
