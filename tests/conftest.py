import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_TMP = Path(tempfile.mkdtemp(prefix="zs-tests-"))
os.environ.update({
    "DATABASE_URL": f"sqlite:///{_TMP / 'test.db'}",
    "DISCOVERY_GIT_ROOT": str(_TMP / "repos"),
    "LOG_FOLLOW_ENABLED": "false",
    "THREAT_INTEL_MODE": "offline",
    "THREAT_CACHE_DIR": str(_TMP / "threat_cache"),
    "JWT_SECRET": "test-secret-that-is-long-enough-for-hs256-signing",
    "LAB_CONFIG_PATH": "",
    "GATEWAY_RULES_DIR": str(_TMP / "gateway-rules"),
})
sys.path.insert(0, str(ROOT / "backend"))
(_TMP / "repos").mkdir()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import engine  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def login(client, username="analyst", password="zombieshield-analyst") -> dict:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def analyst(client):
    return login(client)


@pytest.fixture
def admin_headers(client):
    return login(client, "admin", "zombieshield-admin")


def git(repo: Path, *args: str, date: str = "2025-01-01T10:00:00+00:00") -> None:
    env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date, "GIT_AUTHOR_NAME": "Dev", "GIT_AUTHOR_EMAIL": "dev@example.test",
           "GIT_COMMITTER_NAME": "Dev", "GIT_COMMITTER_EMAIL": "dev@example.test"}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


@pytest.fixture
def shop_repo() -> Path:
    """A tiny FastAPI service whose history retires a v1 route and adds v2."""
    repo = _TMP / "repos" / "shop"
    if repo.exists():
        shutil.rmtree(repo, ignore_errors=True)
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    (repo / "app.py").write_text(
        'from fastapi import APIRouter, FastAPI\napp = FastAPI()\nv1 = APIRouter(prefix="/v1")\n\n'
        '@v1.get("/customers/{customer_id}")\ndef get_customer(customer_id: int): ...\n\n'
        '@app.get("/health")\ndef health(): ...\n')
    (repo / "openapi.yaml").write_text(
        "openapi: 3.0.3\ninfo: {title: shop, version: '1.0'}\npaths:\n  /v1/customers/{customerId}:\n    get: {responses: {'200': {description: ok}}}\n"
        "  /health:\n    get: {responses: {'200': {description: ok}}}\n")
    (repo / "requirements.txt").write_text("jinja2==3.1.2\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "Initial v1 API", date="2024-01-10T10:00:00+00:00")
    (repo / "app.py").write_text(
        'from fastapi import APIRouter, FastAPI\napp = FastAPI()\nv2 = APIRouter(prefix="/v2")\n\n'
        '@v2.get("/customers/{customer_id}")\ndef get_customer(customer_id: int): ...\n\n'
        '@app.get("/health")\ndef health(): ...\n')
    (repo / "openapi.yaml").write_text(
        "openapi: 3.0.3\ninfo: {title: shop, version: '2.0'}\npaths:\n  /v2/customers/{customerId}:\n    get: {responses: {'200': {description: ok}}}\n"
        "  /health:\n    get: {responses: {'200': {description: ok}}}\n  /v2/legacy-report:\n    get: {deprecated: true, responses: {'200': {description: ok}}}\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "Replace v1 customers API with v2", date="2025-03-01T10:00:00+00:00")
    return repo
