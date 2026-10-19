"""Train the endpoint-intelligence models on real public API specifications.

Two binary tasks, both predicted from METHOD + PATH only:
  * legacy      - P(operation is deprecated by its publisher)
  * sensitive   - P(operation handles personal data / secrets), weak label from documented schemas
Evaluation holds out whole API *providers* (GroupShuffleSplit) so that the model is always
scored on organisations it never saw during training.

Usage: python scripts/train_endpoint_model.py --dataset data/endpoint_dataset.csv.gz
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_curve, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import make_pipeline

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.services.ml.text_features import LEGACY_FEATURES, legacy_features, path_tokens, tokens_to_text  # noqa: E402

SEED = 42


def featurize(frame: pd.DataFrame) -> list[str]:
    texts = []
    for method, path, newer in zip(frame["method"], frame["path"], frame["newer_version_exists"]):
        tokens = path_tokens(method, path)
        if newer:
            tokens.append("newer_version_exists")
        texts.append(tokens_to_text(tokens))
    return texts


def vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(analyzer=str.split, min_df=3, max_features=40000, sublinear_tf=True, lowercase=False)


def best_threshold(y_true, scores) -> float:
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    f1 = 2 * precision * recall / np.clip(precision + recall, 1e-9, None)
    return float(thresholds[int(np.nanargmax(f1[:-1]))]) if len(thresholds) else 0.5


def metrics(y_true, scores, threshold) -> dict:
    predicted = (scores >= threshold).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y_true, predicted, average="binary", zero_division=0)
    base = float(np.mean(y_true))
    pr_auc = float(average_precision_score(y_true, scores))
    return {
        "threshold": round(threshold, 4), "precision": round(float(p), 4), "recall": round(float(r), 4), "f1": round(float(f), 4),
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4), "pr_auc": round(pr_auc, 4), "base_rate": round(base, 4),
        "pr_auc_lift_over_random": round(pr_auc / base, 2) if base else None,
        "confusion_matrix": confusion_matrix(y_true, predicted, labels=[0, 1]).astype(int).tolist(), "n_test": int(len(y_true)),
    }


def candidates() -> dict:
    return {
        "Logistic Regression": make_pipeline(vectorizer(), LogisticRegression(max_iter=3000, C=2.0, class_weight="balanced", random_state=SEED)),
        "Complement Naive Bayes": make_pipeline(vectorizer(), ComplementNB(alpha=0.5)),
        "Random Forest": make_pipeline(vectorizer(), RandomForestClassifier(n_estimators=200, min_samples_leaf=3, class_weight="balanced_subsample", n_jobs=-1, random_state=SEED)),
    }


def train_task(frame: pd.DataFrame, features, label: str, factory=None) -> tuple[object, dict]:
    factory = factory or candidates
    texts = features
    y = frame[label].to_numpy()
    groups = frame["provider"].to_numpy()
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=SEED)
    train_idx, test_idx = next(splitter.split(texts, y, groups))
    # validation split inside training providers for threshold selection
    inner = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED + 1)
    fit_idx, val_idx = next(inner.split(train_idx, y[train_idx], groups[train_idx]))
    fit_idx, val_idx = train_idx[fit_idx], train_idx[val_idx]
    x = np.array(texts, dtype=object) if isinstance(texts, list) else np.asarray(texts)
    comparison, fitted = [], {}
    for name, model in factory().items():
        model.fit(x[fit_idx], y[fit_idx])
        threshold = best_threshold(y[val_idx], model.predict_proba(x[val_idx])[:, 1])
        result = metrics(y[test_idx], model.predict_proba(x[test_idx])[:, 1], threshold)
        comparison.append({"name": name, **result})
        fitted[name] = (model, threshold)
        print(label, name, result["pr_auc"], result["f1"])
    best = max(comparison, key=lambda item: item["roc_auc"])
    for item in comparison:
        item["selected"] = item["name"] == best["name"]
    model, threshold = fitted[best["name"]]
    final = factory()[best["name"]]
    final.fit(x[train_idx], y[train_idx])  # refit on all training providers; test providers stay unseen
    summary = {
        "label": label, "selected_model": best["name"], "selection_rule": "highest ROC-AUC on held-out providers (PR-AUC is unstable with ~100 held-out positives)",
        "threshold": threshold, "train_rows": int(len(train_idx)), "test_rows": int(len(test_idx)),
        "train_providers": int(len(set(groups[train_idx]))), "test_providers": int(len(set(groups[test_idx]))),
        "comparison": comparison,
    }
    return (final, threshold), summary


def legacy_candidates() -> dict:
    return {
        "Gradient Boosting (structural)": HistGradientBoostingClassifier(max_depth=3, learning_rate=0.05, max_iter=200, class_weight="balanced", random_state=SEED),
        "Logistic Regression (structural)": LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED),
    }


def legacy_matrix(frame: pd.DataFrame) -> np.ndarray:
    return np.array([legacy_features(m, n, v, vs, rv) for m, n, v, vs, rv in zip(
        frame["method"], frame["newer_version_exists"], frame["path_version"], frame["versions_in_spec"], frame["resource_versions"])], dtype=float)


def top_terms(model, n=15) -> dict:
    vec = model.steps[0][1]
    clf = model.steps[-1][1]
    if not hasattr(clf, "coef_"):
        if hasattr(clf, "feature_importances_"):
            names = vec.get_feature_names_out()
            order = np.argsort(clf.feature_importances_)[::-1][:n]
            return {"most_important": [[names[i], round(float(clf.feature_importances_[i]), 4)] for i in order]}
        return {}
    names = vec.get_feature_names_out()
    coef = clf.coef_[0]
    order = np.argsort(coef)
    return {"raises_probability": [[names[i], round(float(coef[i]), 3)] for i in order[::-1][:n]],
            "lowers_probability": [[names[i], round(float(coef[i]), 3)] for i in order[:n]]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=ROOT / "data" / "endpoint_dataset.csv.gz")
    parser.add_argument("--out", type=Path, default=ROOT / "ml_artifacts")
    args = parser.parse_args()
    frame = pd.read_csv(args.dataset).drop_duplicates(subset=["provider", "api", "method", "path"]).reset_index(drop=True)
    texts = featurize(frame)
    # Negative baseline: path vocabulary alone does not transfer across providers.
    _, vocabulary_baseline = train_task(frame, texts, "deprecated")
    legacy, legacy_summary = train_task(frame, legacy_matrix(frame), "deprecated", legacy_candidates)
    legacy_summary["features"] = list(LEGACY_FEATURES)
    legacy_summary["negative_baseline_path_vocabulary"] = vocabulary_baseline["comparison"]
    sensitive, sensitive_summary = train_task(frame, texts, "sensitive")
    joblib.dump({"legacy": legacy, "sensitive": sensitive}, args.out / "endpoint_model.joblib", compress=3)
    by_newer = frame.groupby("newer_version_exists")["deprecated"].agg(["mean", "count"]).reset_index().to_dict(orient="records")
    report = {
        "model": "endpoint_intelligence",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "source": "APIs.guru openapi-directory (github.com/APIs-guru/openapi-directory)",
            "operations": int(len(frame)), "providers": int(frame["provider"].nunique()), "apis": int(frame["api"].nunique()),
            "deprecated_rate": round(float(frame["deprecated"].mean()), 4), "sensitive_rate": round(float(frame["sensitive"].mean()), 4),
            "deprecation_rate_by_newer_version_exists": [{k: (round(v, 4) if isinstance(v, float) else v) for k, v in row.items()} for row in by_newer],
        },
        "features": "TF-IDF over method, path depth, parameter positions, version segment and camel/snake-split path words; plus 'newer_version_exists'",
        "evaluation": "GroupShuffleSplit by provider (25% of providers held out entirely); threshold chosen on an inner provider-held-out validation split",
        "tasks": {"legacy": legacy_summary, "sensitive": {**sensitive_summary, "top_terms": top_terms(sensitive[0])}},
        "limitations": [
            "Publishers mark only a small fraction of retired operations as deprecated, so 'legacy' labels are incomplete (positive-unlabelled).",
            "The sensitivity label is derived from documented schema field names, not from observed data.",
            "Public APIs over-represent large cloud providers (e.g. azure.com, amazonaws.com).",
        ],
    }
    (args.out / "endpoint_model_metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({t: {k: report["tasks"][t][k] for k in ("selected_model", "threshold")} for t in report["tasks"]}, indent=2))


if __name__ == "__main__":
    main()
