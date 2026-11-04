from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import factory  # noqa: E402

from dfa.config import Settings  # noqa: E402


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory) -> dict[str, Path]:
    return factory.generate_all(tmp_path_factory.mktemp("fixtures"))


@pytest.fixture()
def settings(tmp_path) -> Settings:
    # Real external tools (cwe_checker, Ghidra) are exercised in test_real_tools.py; the generic
    # pipeline/API tests point them at a non-existent image so they report "unavailable" quickly.
    return Settings(data_dir=tmp_path / "data", sandbox_mode="local", fact_url=None,
                    cwe_checker_image="dfa-test/nonexistent-cwe-checker:none",
                    ghidra_image="dfa-test/nonexistent-ghidra:none", worker_mode="external",
                    max_upload_mb=64)


ADMIN_PASSWORD = "correct-horse-battery-staple"


def login(c, username="admin", password=ADMIN_PASSWORD):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    c.headers["X-DFA-CSRF"] = "1"  # cookie-authenticated state-changing requests need the CSRF header
    return r.json()


@pytest.fixture()
def make_client(settings):
    """Factory for authenticated TestClients (bootstrap admin)."""
    from fastapi.testclient import TestClient

    from dfa.main import create_app
    settings.bootstrap_admin = "admin"
    settings.bootstrap_admin_password = ADMIN_PASSWORD
    clients = []

    def _make(start_worker: bool = False, authenticate: bool = True):
        c = TestClient(create_app(settings, start_worker=start_worker))
        c.__enter__()
        clients.append(c)
        if authenticate:
            login(c)
        return c

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


@pytest.fixture()
def client(make_client):
    return make_client()


@pytest.fixture()
def run_analysis(tmp_path):
    """Run the sandbox-side analysis in-process and return the manifest."""
    from dfa.core.analyze import run
    from dfa.core.limits import Limits

    def _run(path: Path, limits: Limits | None = None, name: str | None = None) -> dict:
        import uuid
        work = tmp_path / f"work_{path.name}_{uuid.uuid4().hex[:6]}"
        return run(path, name or path.name, work, limits or Limits())
    return _run
