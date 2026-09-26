"""
SentinelForge Core Configuration

Centralized settings using pydantic-settings. Every value is loaded from
environment variables (or a local .env file). No credential is ever
hardcoded in the repository -- see .env.example for the full list.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> backend/app/core -> backend/app -> backend
REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Every variable is namespaced with ``SENTINELFORGE_``. Without the prefix,
    generic names such as ``DEBUG`` or ``HOST`` would be silently picked up
    from the surrounding shell or a container runtime's injected environment.
    """

    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        env_prefix="SENTINELFORGE_",
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    app_name: str = "SentinelForge"
    app_version: str = "0.1.0"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = True
    log_level: str = "INFO"
    secret_key: str = "change-me-in-production"
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
    )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    # SQLite for local dev, PostgreSQL for production.
    database_url: str = "sqlite+aiosqlite:///./sentinelforge.db"
    db_echo: bool = False

    # ------------------------------------------------------------------
    # AI provider  ("mock" | "ibm_watsonx")
    # ------------------------------------------------------------------
    ai_provider: Literal["mock", "ibm_watsonx"] = "mock"
    ai_temperature: float = 0.1
    ai_max_tokens: int = 4096
    ai_timeout_seconds: int = 120
    ai_max_retries: int = 2

    # IBM watsonx.ai / Granite
    ibm_watsonx_url: str = "https://us-south.ml.cloud.ibm.com"
    ibm_watsonx_api_key: Optional[str] = None
    ibm_watsonx_project_id: Optional[str] = None
    ibm_model_id: str = "ibm/granite-3-8b-instruct"

    # ------------------------------------------------------------------
    # Sandbox  (see app/sandbox -- Docker is the only secure backend)
    # ------------------------------------------------------------------
    # "docker"     : isolated container per verification run (production)
    # "local"      : subprocess fallback, DEV ONLY, never use for untrusted code
    sandbox_backend: Literal["docker", "local"] = "local"
    docker_host: str = "unix:///var/run/docker.sock"
    sandbox_image: str = "python:3.12-slim"
    sandbox_timeout: int = 300
    sandbox_memory_limit: str = "512m"
    sandbox_cpu_limit: float = 1.0
    sandbox_pids_limit: int = 256
    sandbox_network: str = "none"
    sandbox_allow_local_fallback: bool = True
    #: How long a prepared container stays alive before it self-terminates.
    sandbox_container_lifetime: int = 900
    #: Environment forced on every sandbox process.
    sandbox_env: dict[str, str] = Field(
        default_factory=lambda: {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONHASHSEED": "0",
            "HOME": "/tmp",
            "TMPDIR": "/tmp",
        }
    )
    # Hard ceiling on how long any single scanner subprocess may run.
    scanner_timeout: int = 120

    # ------------------------------------------------------------------
    # Uploads / ingestion
    # ------------------------------------------------------------------
    # Relative paths resolve against `data_dir`, so DATA_DIRNAME alone moves
    # all runtime state. Untrusted, user-supplied code is therefore extracted
    # outside the source tree: one directory to mount as a volume, one to
    # exclude from version control, and no chance of it being picked up by a
    # scan of this repository itself.
    upload_dir: str = "uploads"
    workspace_dir: str = "workspaces"
    #: Root for all generated runtime state (sqlite file, sandbox staging).
    data_dirname: str = "./data"
    max_upload_size: int = 104_857_600  # 100 MB
    # Guard against zip bombs during extraction.
    max_uncompressed_size: int = 1_073_741_824  # 1 GiB
    max_archive_files: int = 20_000
    max_file_size: int = 33_554_432  # 32 MiB per file
    supported_languages: list[str] = Field(
        default_factory=lambda: ["python", "javascript", "typescript", "go", "java"]
    )
    primary_language: str = "python"

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------
    max_repair_attempts: int = 2
    finding_confidence_threshold: float = 0.5
    max_findings_per_agent: int = 500
    max_tests_generated: int = 200
    #: Distinct files the Testing Agent writes tests for in one scan.
    max_test_targets: int = 8

    # ------------------------------------------------------------------
    # Frontend
    # ------------------------------------------------------------------
    next_public_api_url: str = "http://localhost:8000"

    # ------------------------------------------------------------------
    # Derived paths
    # ------------------------------------------------------------------
    base_dir: Path = REPO_ROOT

    @field_validator("cors_origins", "supported_languages", mode="before")
    @classmethod
    def _split_csv(cls, value):
        """Allow ``a,b,c`` in .env as well as a real JSON list."""
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):
                return value
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @property
    def upload_path(self) -> Path:
        """Where archives are staged before extraction."""
        return self._runtime_dir(self.upload_dir)

    @property
    def workspace_path(self) -> Path:
        """Root for extracted (untrusted) repository sources."""
        return self._runtime_dir(self.workspace_dir)

    def _runtime_dir(self, configured: str) -> Path:
        """
        Resolve a runtime directory.

        A relative path is resolved against ``data_dir`` rather than the
        repository root, so ``DATA_DIRNAME`` is the single knob that moves all
        mutable state -- useful in tests and when running against a mounted
        volume. An absolute path is always taken as given, which preserves the
        original behaviour for deployments that configure it explicitly.
        """
        path = Path(configured)
        return path if path.is_absolute() else (self.data_dir / path)

    @property
    def data_dir(self) -> Path:
        """Writable runtime directory for databases, uploads and sandboxes."""
        path = Path(self.data_dirname)
        resolved = path if path.is_absolute() else (self.base_dir / path)
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor for FastAPI dependency injection."""
    return Settings()


settings = get_settings()
