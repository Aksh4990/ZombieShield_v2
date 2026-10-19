"""Endpoint intelligence: P(legacy) and P(handles sensitive data) learned from real public API specs."""

import json
import logging
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import API
from app.services.ml.text_features import LEGACY_FEATURES, legacy_features, path_tokens, tokens_to_text
from app.services.normalization import resource_key, version_from_path, version_number

log = logging.getLogger(__name__)
_LEGACY_TEXT = {
    "newer_version_exists": "a newer version of this resource exists",
    "has_version": "path carries an explicit version segment",
    "path_version": "version number in the path",
    "versions_in_service": "number of API versions the service exposes",
    "resource_versions": "number of versions of this resource",
    "is_delete": "DELETE operation",
}


@lru_cache(maxsize=1)
def _bundle() -> dict | None:
    path = Path(get_settings().ml_artifacts_dir) / "endpoint_model.joblib"
    if not path.is_file():
        log.warning("Endpoint model artifact not found at %s", path)
        return None
    try:
        import joblib

        return joblib.load(path)
    except Exception as exc:
        log.warning("Endpoint model could not be loaded (%s)", exc)
        return None


def available() -> bool:
    return _bundle() is not None


def metrics() -> dict | None:
    path = Path(get_settings().ml_artifacts_dir) / "endpoint_model_metrics.json"
    return json.loads(path.read_text()) if path.is_file() else None


def _sensitive_terms(model, text: str, limit: int = 4) -> list[str]:
    vectorizer = model.steps[0][1]
    row = vectorizer.transform([text])
    names = vectorizer.get_feature_names_out()
    classifier = model.steps[-1][1]
    weights = getattr(classifier, "feature_importances_", None)
    if weights is None and hasattr(classifier, "coef_"):
        weights = classifier.coef_[0]
    if weights is None:
        return []
    contributions = [(names[i], float(row[0, i] * weights[i])) for i in row.nonzero()[1]]
    contributions.sort(key=lambda item: item[1], reverse=True)
    return [name for name, value in contributions[:limit] if value > 0 and not name.startswith(("depth_", "params_"))]


def score_inventory(db: Session) -> int:
    bundle = _bundle()
    if bundle is None:
        return 0
    legacy_model, legacy_threshold = bundle["legacy"]
    sensitive_model, sensitive_threshold = bundle["sensitive"]
    apis = list(db.scalars(select(API)))
    # Service-level context computed from the inventory exactly as the training data was computed per spec.
    newest: dict[tuple[str, str], float] = defaultdict(lambda: -1.0)
    service_versions: dict[str, set] = defaultdict(set)
    resource_versions: dict[tuple[str, str], set] = defaultdict(set)
    for api in apis:
        key = (api.service_name, resource_key(api.endpoint_path))
        number = version_number(version_from_path(api.endpoint_path))
        newest[key] = max(newest[key], number)
        if number >= 0:
            service_versions[api.service_name].add(number)
        resource_versions[key].add(number)
    rows, texts = [], []
    for api in apis:
        key = (api.service_name, resource_key(api.endpoint_path))
        number = version_number(version_from_path(api.endpoint_path))
        newer = number >= 0 and newest[key] > number
        rows.append(legacy_features(api.http_method, newer, number, len(service_versions[api.service_name]), len(resource_versions[key])))
        texts.append(tokens_to_text(path_tokens(api.http_method, api.endpoint_path)))
    if not apis:
        return 0
    legacy_scores = legacy_model.predict_proba(np.array(rows))[:, 1]
    sensitive_scores = sensitive_model.predict_proba(np.array(texts, dtype=object))[:, 1]
    for api, row, text, legacy, sensitive in zip(apis, rows, texts, legacy_scores, sensitive_scores):
        api.ml_legacy_score = round(float(legacy), 4)
        api.ml_sensitivity_score = round(float(sensitive), 4)
        reasons = [_LEGACY_TEXT[name] for name, value in zip(LEGACY_FEATURES, row) if value and name in {"newer_version_exists", "has_version", "is_delete"}]
        api.ml_explanation = [
            {"model": "legacy", "score": api.ml_legacy_score, "threshold": round(legacy_threshold, 4), "flagged": bool(legacy >= legacy_threshold),
             "signals": reasons, "trained_on": "84,471 operations from 682 public API providers (APIs.guru)"},
            {"model": "sensitive", "score": api.ml_sensitivity_score, "threshold": round(sensitive_threshold, 4), "flagged": bool(sensitive >= sensitive_threshold),
             "signals": _sensitive_terms(sensitive_model, text), "trained_on": "schema field names of the same public API operations (weak label)"},
        ]
    return len(apis)


def thresholds() -> dict:
    bundle = _bundle()
    if bundle is None:
        return {}
    return {"legacy": float(bundle["legacy"][1]), "sensitive": float(bundle["sensitive"][1])}
