"""Train the request-payload attack classifier on two public, labelled datasets.

Datasets (not redistributed; download them yourself and pass their paths):
  * HTTP CSIC 2010 (Spanish National Research Council) - 36,000 normal + 25,065 anomalous requests.
    CSV export used here: github.com/msudol/Web-Application-Attack-Datasets (CSVData/csic_final.csv)
  * HttpParamsDataset - 31,067 labelled parameter values (norm / sqli / xss / cmdi / path-traversal).
    github.com/Morzeux/HttpParamsDataset (MIT licence)

Usage:
  python scripts/train_payload_model.py --csic path/to/csic_final.csv --httpparams path/to/HttpParamsDataset
Outputs ml_artifacts/payload_model.joblib and ml_artifacts/payload_model_metrics.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import make_pipeline
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from urllib.parse import quote_plus  # noqa: E402

from app.services.ml.text_features import payload_text  # noqa: E402

SEED = 42
THRESHOLD = 0.85  # favours precision: a false alarm on ordinary traffic costs more than a missed probe


def load_csic(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, usecols=["Class", "Method", "URI", "POST-Data", "GET-Query"], dtype=str, keep_default_na=False)
    texts = [payload_text(uri, query, body) for uri, query, body in zip(frame["URI"], frame["GET-Query"], frame["POST-Data"])]
    out = pd.DataFrame({"text": texts, "label": (frame["Class"] != "Valid").astype(int), "type": "unknown", "dataset": "csic2010"})
    raw = frame["URI"] + "?" + frame["GET-Query"] + "#" + frame["POST-Data"]
    out["raw"] = raw
    return out.drop_duplicates(subset=["raw", "label"]).drop(columns=["raw"])


def load_httpparams(directory: Path) -> pd.DataFrame:
    frames = []
    for split in ("payload_train.csv", "payload_test.csv"):
        frame = pd.read_csv(directory / split, dtype=str, keep_default_na=False)
        frames.append(pd.DataFrame({
            "text": [payload_text("/", "v=" + quote_plus(value)) for value in frame["payload"]], "label": (frame["label"] != "norm").astype(int), "type": frame["attack_type"],
            "dataset": "httpparams", "split": "train" if "train" in split else "test",
        }))
    return pd.concat(frames, ignore_index=True)


def binary_metrics(y_true, scores, threshold=THRESHOLD) -> dict:
    predicted = (scores >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, predicted, average="binary", zero_division=0)
    return {
        "precision": round(float(precision), 4), "recall": round(float(recall), 4), "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4), "pr_auc": round(float(average_precision_score(y_true, scores)), 4),
        "confusion_matrix": confusion_matrix(y_true, predicted, labels=[0, 1]).astype(int).tolist(), "n": int(len(y_true)),
    }


def scores(model, texts: pd.Series) -> np.ndarray:
    """Inert requests (empty text after the structural pre-filter) score 0 without calling the model."""
    out = np.zeros(len(texts))
    mask = texts.str.len().to_numpy() > 0
    if mask.any():
        out[mask] = model.predict_proba(texts[mask])[:, 1]
    return out


def vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(1, 4), min_df=2, max_features=60000, sublinear_tf=True, lowercase=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csic", type=Path, required=True)
    parser.add_argument("--httpparams", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "ml_artifacts")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    csic = load_csic(args.csic)
    params = load_httpparams(args.httpparams)
    csic_train, csic_test = train_test_split(csic, test_size=0.25, random_state=SEED, stratify=csic["label"])
    params_train, params_test = params[params["split"] == "train"], params[params["split"] == "test"]
    train = pd.concat([csic_train, params_train], ignore_index=True)
    train = train[train["text"].str.len() > 0]

    candidates = {
        "Complement Naive Bayes": make_pipeline(vectorizer(), ComplementNB(alpha=0.3)),
        "Logistic Regression": make_pipeline(vectorizer(), LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced", random_state=SEED)),
        "Linear SVM (calibrated)": make_pipeline(vectorizer(), CalibratedClassifierCV(LinearSVC(C=0.5, class_weight="balanced", random_state=SEED), cv=3)),
    }
    comparison = []
    fitted = {}
    for name, model in candidates.items():
        model.fit(train["text"], train["label"])
        fitted[name] = model
        csic_scores = scores(model, csic_test["text"])
        params_scores = scores(model, params_test["text"])
        comparison.append({
            "name": name,
            "csic2010_test": binary_metrics(csic_test["label"].to_numpy(), csic_scores),
            "httpparams_test": binary_metrics(params_test["label"].to_numpy(), params_scores),
        })
        print(name, comparison[-1]["csic2010_test"]["f1"], comparison[-1]["httpparams_test"]["f1"])

    # Model selection by mean PR-AUC over both held-out sets (not by accuracy).
    best = max(comparison, key=lambda item: (item["csic2010_test"]["pr_auc"] + item["httpparams_test"]["pr_auc"]) / 2)
    best_name = best["name"]
    for item in comparison:
        item["selected"] = item["name"] == best_name

    # Cross-dataset generalisation: train on CSIC only, test on the independent HttpParams test split.
    cross = make_pipeline(vectorizer(), LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced", random_state=SEED))
    cross_train = csic_train[csic_train["text"].str.len() > 0]
    cross.fit(cross_train["text"], cross_train["label"])
    cross_metrics = binary_metrics(params_test["label"].to_numpy(), scores(cross, params_test["text"]))

    # Attack-type model (HttpParams has per-family labels).
    attacks_train = params_train[(params_train["label"] == 1) & (params_train["text"].str.len() > 0)]
    attacks_test = params_test[(params_test["label"] == 1) & (params_test["text"].str.len() > 0)]
    type_model = make_pipeline(vectorizer(), LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced", random_state=SEED))
    type_model.fit(attacks_train["text"], attacks_train["type"])
    type_report = classification_report(attacks_test["type"], type_model.predict(attacks_test["text"]), output_dict=True, zero_division=0)

    joblib.dump({"binary": fitted[best_name], "type": type_model, "threshold": THRESHOLD, "name": best_name}, args.out / "payload_model.joblib", compress=3)
    metrics = {
        "model": "payload_attack_classifier",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "selected_model": best_name,
        "decision_threshold": THRESHOLD,
        "selection_rule": "highest mean PR-AUC across the CSIC 2010 and HttpParams held-out test sets",
        "features": "TF-IDF character 1-4 grams over parameter values and unusual path segments only (no parameter names, no ordinary paths)",
        "pre_filter": "values made only of letters, digits, spaces and . , @ + - (no '--') are treated as inert and score 0; every test row is still counted in the metrics",
        "inert_share": {"csic2010_test": round(float((csic_test["text"].str.len() == 0).mean()), 4), "httpparams_test": round(float((params_test["text"].str.len() == 0).mean()), 4)},
        "datasets": {
            "csic2010": {"rows_after_dedup": int(len(csic)), "train": int(len(csic_train)), "test": int(len(csic_test)), "attack_share": round(float(csic["label"].mean()), 4),
                         "source": "HTTP CSIC 2010, CSV export from github.com/msudol/Web-Application-Attack-Datasets"},
            "httpparams": {"train": int(len(params_train)), "test": int(len(params_test)), "attack_share": round(float(params["label"].mean()), 4),
                           "source": "github.com/Morzeux/HttpParamsDataset (MIT)"},
        },
        "comparison": comparison,
        "cross_dataset_generalisation": {"train": "CSIC 2010 only", "test": "HttpParams test split", **cross_metrics},
        "attack_type_report": {k: v for k, v in type_report.items() if isinstance(v, dict)},
        "limitations": [
            "CSIC 2010 traffic was generated against a single e-commerce application in 2010; real traffic will differ.",
            "CSIC 'anomalous' requests include unusual-but-benign values, which lowers achievable precision.",
            "The classifier inspects URL parameter values only; request bodies are not present in gateway access logs.",
        ],
    }
    (args.out / "payload_model_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps({k: metrics[k] for k in ("selected_model", "cross_dataset_generalisation")}, indent=2))


if __name__ == "__main__":
    np.random.seed(SEED)
    main()
