"""Request-payload attack classifier (trained on HTTP CSIC 2010 + HttpParamsDataset)."""

import json
import logging
from functools import lru_cache
from pathlib import Path

from app.core.config import get_settings
from app.services.ml.text_features import payload_text

log = logging.getLogger(__name__)


class PayloadClassifier:
    def __init__(self, bundle: dict):
        self.binary = bundle["binary"]
        self.type_model = bundle["type"]
        self.threshold = float(bundle.get("threshold", 0.5))
        self.name = bundle.get("name", "payload model")

    def classify(self, path: str, query: str, body: str | None = None) -> tuple[str, float | None]:
        text = payload_text(path, query, body)
        if not text:
            return "normal", None
        score = float(self.binary.predict_proba([text])[0][1])
        if score < self.threshold:
            return "normal", round(score, 4)
        return str(self.type_model.predict([text])[0]), round(score, 4)


@lru_cache(maxsize=1)
def get_classifier() -> PayloadClassifier | None:
    path = Path(get_settings().ml_artifacts_dir) / "payload_model.joblib"
    if not path.is_file():
        log.warning("Payload model artifact not found at %s; payload classification disabled", path)
        return None
    try:
        import joblib

        return PayloadClassifier(joblib.load(path))
    except Exception as exc:  # incompatible scikit-learn version etc.
        log.warning("Payload model could not be loaded (%s); payload classification disabled", exc)
        return None


def metrics() -> dict | None:
    path = Path(get_settings().ml_artifacts_dir) / "payload_model_metrics.json"
    return json.loads(path.read_text()) if path.is_file() else None
