"""Compare ZombieShield's lifecycle classifications with an independently written ground truth.

Ground-truth file (JSON):
{
  "name": "Sock Shop v1",
  "endpoints": [
    {"service": "front-end", "method": "PUT", "path": "/cart/{id}", "expected": "ZOMBIE", "note": "removed 2017, old client still calls it"},
    ...
  ]
}
`expected` is one of ACTIVE, DEPRECATED, SHADOW, ZOMBIE, DECOMMISSIONED.
"""

from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import API, LifecycleState, ValidationRun
from app.services.normalization import normalize_path

STATES = [state.value for state in LifecycleState]
NOT_FOUND = "NOT_FOUND"


class GroundTruthError(ValueError):
    pass


def _prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn}


def validate(db: Session, truth: dict, label: str = "uploaded") -> ValidationRun:
    entries = truth.get("endpoints")
    if not isinstance(entries, list) or not entries:
        raise GroundTruthError("Ground truth must contain a non-empty 'endpoints' list")
    index: dict[tuple[str, str, str], API] = {}
    for api in db.scalars(select(API)):
        index[(api.service_name, api.http_method, api.endpoint_path)] = api

    rows, pairs = [], []
    for entry in entries:
        try:
            service, method, path, expected = entry["service"], entry["method"].upper(), entry["path"], entry["expected"].upper()
        except (KeyError, AttributeError) as exc:
            raise GroundTruthError(f"Invalid entry {entry!r}: needs service, method, path and expected") from exc
        if expected not in STATES:
            raise GroundTruthError(f"Unknown expected state '{expected}' for {method} {path}")
        api = index.get((service, method, normalize_path(path)))
        predicted = api.lifecycle_state.value if api else NOT_FOUND
        pairs.append((expected, predicted))
        rows.append({"service": service, "method": method, "path": path, "expected": expected, "predicted": predicted,
                     "correct": expected == predicted, "note": entry.get("note"), "reason": api.classification_reason if api else None})

    labels = STATES + [NOT_FOUND]
    counts = Counter(pairs)
    matrix = [[counts.get((actual, predicted), 0) for predicted in labels] for actual in STATES]
    per_class = {}
    for state in STATES:
        tp = counts.get((state, state), 0)
        fp = sum(n for (actual, predicted), n in counts.items() if predicted == state and actual != state)
        fn = sum(n for (actual, predicted), n in counts.items() if actual == state and predicted != state)
        per_class[state] = {**_prf(tp, fp, fn), "support": sum(1 for actual, _ in pairs if actual == state)}

    # Binary view used in the paper: "unmanaged" (ZOMBIE or SHADOW) is the positive class.
    positive = {"ZOMBIE", "SHADOW"}
    tp = sum(1 for a, p in pairs if a in positive and p in positive)
    fp = sum(1 for a, p in pairs if a not in positive and p in positive)
    fn = sum(1 for a, p in pairs if a in positive and p not in positive)
    zombie_only = _prf(counts.get(("ZOMBIE", "ZOMBIE"), 0),
                       sum(n for (a, p), n in counts.items() if p == "ZOMBIE" and a != "ZOMBIE"),
                       sum(n for (a, p), n in counts.items() if a == "ZOMBIE" and p != "ZOMBIE"))
    supported = [s for s in STATES if per_class[s]["support"]]
    metrics = {
        "endpoints": len(pairs),
        "accuracy": round(sum(1 for a, p in pairs if a == p) / len(pairs), 4),
        "macro_f1": round(sum(per_class[s]["f1"] for s in supported) / len(supported), 4) if supported else 0.0,
        "unmanaged_zombie_or_shadow": _prf(tp, fp, fn),
        "zombie": zombie_only,
        "not_found": sum(1 for _, p in pairs if p == NOT_FOUND),
        "per_class": per_class,
        "confusion_matrix": {"rows_actual": STATES, "columns_predicted": labels, "values": matrix},
    }
    run = ValidationRun(ground_truth=str(truth.get("name") or label), metrics=metrics, details={"rows": rows})
    db.add(run)
    db.commit()
    return run
