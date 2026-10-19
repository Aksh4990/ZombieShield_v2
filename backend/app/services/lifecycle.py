"""Evidence-based lifecycle classification.

Definitions used throughout ZombieShield (OWASP API9:2023 Improper Inventory Management):
  ZOMBIE          - was part of the supported surface (in code or in the spec, or superseded by a newer
                    version) and has been retired, yet it still receives runtime traffic.
  SHADOW          - receives runtime traffic but has never appeared in any specification or source
                    code ZombieShield has seen (current *or* historical).
  DEPRECATED      - publisher (spec `deprecated: true`) or owner marked it deprecated; still supported.
  DECOMMISSIONED  - retired and no runtime traffic inside the activity window.
  ACTIVE          - supported by current specification or code.
Rules are evaluated in this order and the first match wins; every result stores its reason.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import API, LifecycleState
from app.services.inventory import as_utc
from app.services.normalization import resource_key, version_number


@dataclass(frozen=True)
class Classification:
    state: LifecycleState
    reason: str


def find_superseded(apis: list[API]) -> dict:
    """Map api.id -> newer path for operations whose resource exists in a higher version that is supported."""
    supported_versions: dict[tuple, list[tuple[float, API]]] = defaultdict(list)
    for api in apis:
        if api.in_current_spec or api.in_current_code:
            supported_versions[(api.host, api.http_method, resource_key(api.endpoint_path))].append((version_number(api.version), api))
    superseded = {}
    for api in apis:
        current = version_number(api.version)
        if current < 0:
            continue
        candidates = [other for number, other in supported_versions.get((api.host, api.http_method, resource_key(api.endpoint_path)), []) if number > current]
        if candidates:
            newest = max(candidates, key=lambda other: version_number(other.version))
            superseded[api.id] = newest.display_path
    return superseded


class LifecycleClassifier:
    def __init__(self, activity_window_days: int = 30):
        self.window = timedelta(days=activity_window_days)

    def classify(self, api: API, now: datetime, superseded_by: str | None = None) -> Classification:
        last_runtime = as_utc(api.last_runtime_seen)
        recent = bool(api.in_runtime and last_runtime and last_runtime >= now - self.window)
        supported = api.in_current_spec or api.in_current_code
        retired_in_history = (api.previously_in_code or api.previously_in_spec) and not supported
        deprecated = api.spec_deprecated or api.manually_deprecated
        removed = api.manually_removed or retired_in_history
        traffic = f"{api.request_count} request(s), last at {last_runtime:%Y-%m-%d %H:%M} UTC" if last_runtime else "no runtime traffic"

        if removed and recent:
            evidence = api.removal_note or "Marked removed from the supported surface by its owner."
            return Classification(LifecycleState.ZOMBIE, f"Retired but still reachable: {evidence} Runtime traffic continues ({traffic}).")
        if superseded_by and recent and (not supported or deprecated):
            return Classification(LifecycleState.ZOMBIE, f"Superseded by {superseded_by}" + (" and deprecated" if deprecated else ", no longer in the current spec or code")
                                  + f", yet still serving traffic ({traffic}).")
        if deprecated:
            source = "specification (deprecated: true)" if api.spec_deprecated else "inventory owner"
            usage = f" Still in use: {traffic}." if recent else " No recent runtime use."
            return Classification(LifecycleState.DEPRECATED, f"Marked deprecated by the {source}.{usage}" + (f" Replacement: {superseded_by}." if superseded_by else ""))
        if removed and not recent:
            return Classification(LifecycleState.DECOMMISSIONED, f"Retired with no runtime traffic in the last {self.window.days} days. " + (api.removal_note or ""))
        if recent and not supported and not (api.previously_in_code or api.previously_in_spec):
            return Classification(LifecycleState.SHADOW, f"Receives runtime traffic ({traffic}) but has never appeared in any specification or source code that was scanned.")
        if supported:
            docs = "documented and implemented" if api.in_current_spec and api.in_current_code else ("documented in the specification" if api.in_current_spec else "implemented in code but NOT documented in any specification")
            usage = f"; {traffic}" if api.in_runtime else "; not observed in runtime traffic yet"
            return Classification(LifecycleState.ACTIVE, f"Supported surface: {docs}{usage}.")
        return Classification(LifecycleState.ACTIVE, "Insufficient evidence to change state; retained as ACTIVE to avoid a false lifecycle change.")


def classify_inventory(db: Session, activity_window_days: int = 30, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(timezone.utc)
    apis = list(db.scalars(select(API)))
    superseded = find_superseded(apis)
    classifier = LifecycleClassifier(activity_window_days)
    counts: dict[str, int] = defaultdict(int)
    for api in apis:
        api.superseded_by = superseded.get(api.id)
        result = classifier.classify(api, now, api.superseded_by)
        api.lifecycle_state = result.state
        api.classification_reason = result.reason
        api.classified_at = now
        counts[result.state.value] += 1
    return dict(counts)
