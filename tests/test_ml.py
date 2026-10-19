import pytest

from app.services.ml import endpoint_model, payload_model
from app.services.ml.text_features import is_sensitive_name, payload_text


def test_payload_features_ignore_inert_values():
    assert payload_text("/catalogue", "size=6&page=1") == ""
    assert payload_text("/x", "id=1%27+OR+1%3D1") == "1' OR 1=1"
    assert payload_text("/files/..%2F..%2Fetc", "") == "../../etc"


def test_sensitive_field_names_use_whole_tokens():
    assert is_sensitive_name("customerEmail") and is_sensitive_name("card_number") and is_sensitive_name("password")
    assert not is_sensitive_name("nextToken") and not is_sensitive_name("ipAddress") and not is_sensitive_name("zipFile")


def test_payload_classifier_if_artifact_present():
    classifier = payload_model.get_classifier()
    if classifier is None:
        pytest.skip("payload model artifact not present")
    assert classifier.classify("/catalogue", "size=6&page=1")[0] == "normal"
    assert classifier.classify("/x", "id=1' OR '1'='1")[0] == "sqli"
    assert classifier.classify("/x", "q=<script>alert(1)</script>")[0] == "xss"


def test_model_cards_exist():
    if not endpoint_model.available():
        pytest.skip("endpoint model artifact not present")
    card = endpoint_model.metrics()
    assert card["evaluation"].startswith("GroupShuffleSplit by provider")
