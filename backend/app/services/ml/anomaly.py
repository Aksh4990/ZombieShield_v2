"""Behavioural anomaly detection on per-client traffic windows (Isolation Forest).

Each (client, time-window) becomes one feature vector describing *how* the client used
the API surface. The detector is fitted on a baseline period (the earliest part of the
observed traffic, by default) and scores every window. Explanations compare a window's
features with the baseline medians, and a transparent pattern label (enumeration, BOLA
probing, credential stuffing, injection, zombie access) is attached for the analyst.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import API, AnomalyEvent, LifecycleState, RequestLog
from app.services.inventory import as_utc

FEATURES = (
    "requests", "distinct_endpoints", "distinct_object_ids", "max_ids_per_endpoint", "ratio_404", "ratio_401_403",
    "ratio_5xx", "ratio_2xx", "payload_attack_ratio", "unauth_ratio", "retired_endpoint_ratio", "login_failures",
    "write_ratio", "mean_interarrival_s",
)
_LOG_FEATURES = {"requests", "distinct_endpoints", "distinct_object_ids", "max_ids_per_endpoint", "login_failures", "mean_interarrival_s"}
_DESCRIPTIONS = {
    "requests": "request volume", "distinct_endpoints": "number of distinct endpoints touched",
    "distinct_object_ids": "number of distinct object IDs requested", "max_ids_per_endpoint": "object IDs iterated on a single endpoint",
    "ratio_404": "share of 404 Not Found responses", "ratio_401_403": "share of 401/403 responses", "ratio_5xx": "share of server errors",
    "ratio_2xx": "share of successful responses", "payload_attack_ratio": "share of requests flagged by the payload classifier",
    "unauth_ratio": "share of unauthenticated requests", "retired_endpoint_ratio": "share of requests to zombie/shadow/retired endpoints",
    "login_failures": "failed login attempts", "write_ratio": "share of write (POST/PUT/PATCH/DELETE) requests",
    "mean_interarrival_s": "seconds between requests",
}
_RETIRED = {LifecycleState.ZOMBIE, LifecycleState.SHADOW, LifecycleState.DECOMMISSIONED}


@dataclass
class Window:
    client: str
    start: datetime
    end: datetime
    features: dict[str, float]
    endpoints: Counter


def _windows(db: Session, window_seconds: int) -> list[Window]:
    lifecycle = dict(db.execute(select(API.id, API.lifecycle_state)).all())
    groups: dict[tuple[str, int], list] = defaultdict(list)
    for row in db.execute(select(RequestLog.client_hash, RequestLog.ts, RequestLog.method, RequestLog.path, RequestLog.status,
                                 RequestLog.raw_id, RequestLog.payload_label, RequestLog.authenticated, RequestLog.api_id)
                          .where(RequestLog.client_hash.is_not(None)).order_by(RequestLog.ts)):
        ts = as_utc(row.ts)
        groups[(row.client_hash, int(ts.timestamp()) // window_seconds)].append(row)
    windows = []
    for (client, bucket), rows in groups.items():
        n = len(rows)
        ids_per_endpoint: dict[str, set] = defaultdict(set)
        endpoints: Counter = Counter()
        for row in rows:
            endpoints[f"{row.method} {row.path}"] += 1
            if row.raw_id:
                ids_per_endpoint[f"{row.method} {row.path}"].add(row.raw_id)
        times = sorted(as_utc(row.ts).timestamp() for row in rows)
        gaps = np.diff(times) if len(times) > 1 else np.array([float(window_seconds)])
        features = {
            "requests": n,
            "distinct_endpoints": len(endpoints),
            "distinct_object_ids": len({row.raw_id for row in rows if row.raw_id}),
            "max_ids_per_endpoint": max((len(v) for v in ids_per_endpoint.values()), default=0),
            "ratio_404": sum(row.status == 404 for row in rows) / n,
            "ratio_401_403": sum(row.status in (401, 403) for row in rows) / n,
            "ratio_5xx": sum(row.status >= 500 for row in rows) / n,
            "ratio_2xx": sum(200 <= row.status < 300 for row in rows) / n,
            "payload_attack_ratio": sum(row.payload_label not in (None, "normal") for row in rows) / n,
            "unauth_ratio": sum(row.authenticated is False for row in rows) / n,
            "retired_endpoint_ratio": sum(lifecycle.get(row.api_id) in _RETIRED for row in rows) / n,
            "login_failures": sum(1 for row in rows if "login" in row.path and row.status in (400, 401, 403)),
            "write_ratio": sum(row.method in {"POST", "PUT", "PATCH", "DELETE"} for row in rows) / n,
            "mean_interarrival_s": float(np.mean(gaps)),
        }
        start = datetime.fromtimestamp(bucket * window_seconds, tz=timezone.utc)
        windows.append(Window(client, start, start + timedelta(seconds=window_seconds), features, endpoints))
    return windows


def _vector(features: dict[str, float]) -> list[float]:
    return [float(np.log1p(features[name])) if name in _LOG_FEATURES else float(features[name]) for name in FEATURES]


def _pattern(features: dict[str, float]) -> str:
    if features["payload_attack_ratio"] >= 0.2:
        return "INJECTION_ATTEMPTS"
    if features["login_failures"] >= 5:
        return "CREDENTIAL_STUFFING"
    if features["ratio_404"] >= 0.4 and features["distinct_endpoints"] >= 8:
        return "ENDPOINT_ENUMERATION"
    if features["max_ids_per_endpoint"] >= 8:
        return "OBJECT_ID_ENUMERATION (BOLA probing)"
    if features["retired_endpoint_ratio"] >= 0.5:
        return "RETIRED_ENDPOINT_ACCESS"
    if features["ratio_401_403"] >= 0.5:
        return "AUTHORIZATION_PROBING"
    return "UNUSUAL_BEHAVIOUR"


def _reasons(features: dict[str, float], median: dict[str, float], spread: dict[str, float]) -> list[str]:
    deviations = []
    for name in FEATURES:
        value, centre, scale = features[name], median[name], max(spread[name], 1e-6 if name not in _LOG_FEATURES else 1.0)
        z = (value - centre) / scale
        if abs(z) >= 2 and abs(value - centre) > (0.05 if name not in _LOG_FEATURES else 1):
            deviations.append((abs(z), name, value, centre))
    deviations.sort(reverse=True)
    out = []
    for _, name, value, centre in deviations[:3]:
        fmt = (lambda x: f"{x:.0%}") if name.startswith("ratio") or name.endswith("_ratio") else (lambda x: f"{x:.1f}" if isinstance(x, float) and not x.is_integer() else f"{int(x)}")
        out.append(f"{_DESCRIPTIONS[name].capitalize()} is {fmt(value)} (baseline {fmt(centre)})")
    return out


def detect(db: Session, window_seconds: int = 60, baseline_fraction: float = 0.3, contamination: float | str = "auto") -> dict:
    windows = _windows(db, window_seconds)
    db.execute(delete(AnomalyEvent))
    if len(windows) < 10:
        return {"windows": len(windows), "anomalies": 0, "note": "Not enough traffic windows to fit the detector (need at least 10)."}
    windows.sort(key=lambda w: w.start)
    first, last = windows[0].start, windows[-1].start
    cutoff = first + (last - first) * baseline_fraction
    baseline = [w for w in windows if w.start <= cutoff]
    mode = f"baseline = earliest {int(baseline_fraction * 100)}% of the observation period"
    if len(baseline) < 30:
        baseline, mode = windows, "baseline = all windows (not enough early windows)"
    x_base = np.array([_vector(w.features) for w in baseline])
    model = IsolationForest(n_estimators=300, contamination=contamination, random_state=42).fit(x_base)
    x_all = np.array([_vector(w.features) for w in windows])
    scores = -model.score_samples(x_all)  # higher = more anomalous
    flags = model.predict(x_all) == -1
    base_features = {name: [w.features[name] for w in baseline] for name in FEATURES}
    median = {name: float(np.median(values)) for name, values in base_features.items()}
    spread = {name: float(np.subtract(*np.percentile(values, [75, 25]))) or float(np.std(values)) for name, values in base_features.items()}
    anomalies = 0
    for window, score, flagged in zip(windows, scores, flags):
        if not flagged:
            continue
        anomalies += 1
        db.add(AnomalyEvent(
            client_hash=window.client, window_start=window.start, window_end=window.end, score=round(float(score), 4), is_anomaly=True,
            pattern=_pattern(window.features), features={k: round(float(v), 4) for k, v in window.features.items()},
            reasons=_reasons(window.features, median, spread) or ["Combination of features is rare compared with the baseline"],
            top_endpoints=[endpoint for endpoint, _ in window.endpoints.most_common(5)],
        ))
    db.flush()
    # Endpoint exposure to anomalous clients
    anomalous_clients = {w.client for w, f in zip(windows, flags) if f}
    per_api: dict = defaultdict(set)
    for api_id, client in db.execute(select(RequestLog.api_id, RequestLog.client_hash).where(RequestLog.api_id.is_not(None))):
        if client in anomalous_clients:
            per_api[api_id].add(client)
    for api in db.scalars(select(API)):
        api.anomalous_client_count = len(per_api.get(api.id, ()))
    return {"windows": len(windows), "baseline_windows": len(baseline), "baseline_mode": mode, "anomalies": anomalies,
            "anomalous_clients": len(anomalous_clients), "window_seconds": window_seconds}


def flagged_clients(db: Session) -> set[str]:
    return set(db.scalars(select(AnomalyEvent.client_hash).where(AnomalyEvent.is_anomaly.is_(True))))
