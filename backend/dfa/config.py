"""Application settings (environment variables prefixed with DFA_)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DFA_", env_file=".env", extra="ignore")

    data_dir: Path = BACKEND_DIR / "var"
    database_url: str | None = None  # default: sqlite:///<data_dir>/dfa.db

    # Upload / API
    max_upload_mb: int = 512
    api_key: str | None = None  # if set, required in the X-API-Key header
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Worker
    worker_mode: str = "inprocess"  # inprocess | external
    worker_threads: int = 1
    worker_poll_s: float = 1.0
    max_attempts: int = 2

    # Sandbox for identification/extraction/built-in scanning
    sandbox_mode: str = "auto"  # auto | docker | local
    sandbox_image: str = "dfa-sandbox:latest"
    sandbox_memory: str = "2g"
    sandbox_cpus: str = "2"
    sandbox_pids: int = 256
    sandbox_timeout_s: int = 1800
    sandbox_host_data_dir: Path | None = None  # host path of data_dir when the worker itself runs in Docker
    allow_unsandboxed: bool = True  # permit 'local' fallback when Docker is unavailable

    keep_extracted: bool = True  # False: delete extracted files after a scan (manifest/findings/tool output kept)

    # Extraction limits (see dfa.core.limits.Limits)
    max_extract_total_mb: int = 2048
    max_extract_file_mb: int = 512
    max_extract_files: int = 20000
    max_extract_depth: int = 5
    max_compression_ratio: float = 250.0

    # cwe_checker
    cwe_checker_enabled: bool = True
    cwe_checker_bin: str | None = None  # local install; otherwise Docker image is used
    cwe_checker_image: str = "ghcr.io/fkie-cad/cwe_checker:stable"
    cwe_checker_max_binaries: int = 5
    cwe_checker_timeout_s: int = 900
    cwe_checker_memory: str = "4g"
    cwe_checker_bare_metal: bool = False  # experimental: analyse raw Cortex-M images

    # FwAnalyzer
    fwanalyzer_enabled: bool = True
    fwanalyzer_bin: str | None = None  # defaults to 'fwanalyzer' on PATH
    fwanalyzer_timeout_s: int = 600

    # FACT (external service)
    fact_url: str | None = None  # e.g. http://fact.local:5000
    fact_api_key: str | None = None
    fact_timeout_s: int = 3600
    fact_poll_s: float = 15.0
    fact_max_upload_mb: int = 256
    fact_verify_tls: bool = True

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite:///{self.data_dir / 'dfa.db'}"

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def work_root(self) -> Path:
        return self.data_dir / "work"

    def limits_dict(self) -> dict:
        mb = 1024 * 1024
        return {"max_total_bytes": self.max_extract_total_mb * mb, "max_file_bytes": self.max_extract_file_mb * mb,
                "max_files": self.max_extract_files, "max_depth": self.max_extract_depth,
                "max_ratio": self.max_compression_ratio}

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.uploads_dir, self.work_root):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
