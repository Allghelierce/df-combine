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
    # Authentication: "users" (accounts, roles, tokens) or "disabled" (single-user local development only)
    auth_mode: str = "users"
    bootstrap_admin: str | None = None  # created at startup if no users exist ...
    bootstrap_admin_password: str | None = None  # ... with this password (>= 10 characters)
    session_cookie_secure: bool = False  # set True when served over HTTPS
    upload_rate_per_hour: int = 60  # uploads per user per hour
    max_active_scans_per_user: int = 10  # queued + running
    min_free_disk_mb: int = 2048  # refuse uploads when the data volume is nearly full
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
    sandbox_runtime: str | None = None  # e.g. "runsc" (gVisor) for an additional kernel boundary
    sandbox_max_jobs: int = 2  # concurrent sandbox containers
    max_work_dir_mb: int = 8192  # per-scan work directory cap enforced while containers run
    # largest sandbox-produced manifest the worker/API will parse (JSON expands ~10x in memory; a Debian rootfs
    # with 3,000+ files gives 3.5 MB, and extraction stops at 20,000 files)
    max_manifest_mb: int = 64
    # Sandbox broker: when set, the worker sends jobs to this Unix socket and needs no Docker access.
    broker_socket: Path | None = None
    broker_token: str | None = None

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
    # Docker Hub copy of the official FKIE image (ghcr.io blob storage is blocked in some networks)
    cwe_checker_image: str = "fkiecad/cwe_checker:latest"
    cwe_checker_max_binaries: int = 3
    cwe_checker_timeout_s: int = 3600  # a 2 MB PX4 image takes ~20 min in bare-metal mode
    cwe_checker_memory: str = "4g"
    cwe_checker_bare_metal: bool = True  # raw Cortex-M images (PX4/ArduPilot); experimental upstream

    # Offline vulnerability database (python -m dfa.vulndb update); default <data_dir>/vulndb.sqlite
    vulndb_path: str | None = None

    # Ghidra headless (the cwe_checker image ships Ghidra 11.x at /opt/ghidra)
    ghidra_enabled: bool = True
    ghidra_image: str = "fkiecad/cwe_checker:latest"
    ghidra_memory: str = "6g"
    ghidra_timeout_s: int = 1800
    ghidra_max_binaries: int = 3
    # Host path of dfa/ghidra_scripts when the broker itself runs in a container (bind mounts are resolved
    # by the host daemon); default: the package directory.
    ghidra_scripts_host_dir: Path | None = None

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
    # FACT plug-ins to request. FACT's own cwe_checker plug-in is left out by default: it analyses every
    # ELF of a root filesystem (hours for a Debian image), and cwe_checker already runs here on a bounded
    # selection of binaries. Add "cwe_checker" to opt in.
    fact_plugins: list[str] = ["crypto_material", "users_and_passwords", "software_components", "cve_lookup",
                               "known_vulnerabilities", "exploit_mitigations", "elf_analysis"]

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
