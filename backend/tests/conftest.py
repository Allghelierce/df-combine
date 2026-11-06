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
    return Settings(data_dir=tmp_path / "data", sandbox_mode="local",
                    cwe_checker_image="dfa-test/nonexistent-cwe-checker:none", worker_mode="external",
                    max_upload_mb=64)


@pytest.fixture()
def client(settings):
    from fastapi.testclient import TestClient

    from dfa.main import create_app
    app = create_app(settings, start_worker=False)
    with TestClient(app) as c:
        yield c


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
