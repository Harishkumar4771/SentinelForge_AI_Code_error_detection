"""Shared fixtures.

Two things every test here needs and should not rebuild itself:

* a pointer to the controlled vulnerable demo repository, and
* a Python interpreter that can actually import that repository's dependencies.

The interpreter is resolved *without* ``Path.resolve()`` on purpose. The
virtualenv's ``bin/python`` is a symlink to the base interpreter; resolving it
silently drops the virtualenv's ``site-packages`` and every test that runs
target code then fails on a missing Flask.
"""

from __future__ import annotations

import os
import pathlib
import sys
from collections.abc import AsyncGenerator, Iterator

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO_REPO = REPO_ROOT / "test-projects" / "vulnerable-python-app"

# Make ``app`` importable regardless of the working directory pytest was
# started from.
if str(REPO_ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "backend"))


def _interpreter() -> str:
    """A Python that can import the demo app's dependencies."""
    for candidate in (
        REPO_ROOT / ".venv" / "bin" / "python",
        pathlib.Path(sys.executable),
    ):
        if candidate.exists():
            # absolute(), not resolve(): see the module docstring.
            return str(candidate.absolute())
    return sys.executable


@pytest.fixture(scope="session")
def python_executable() -> str:
    return _interpreter()


@pytest.fixture(scope="session")
def demo_repo() -> pathlib.Path:
    if not DEMO_REPO.is_dir():
        pytest.skip(f"demo repository missing at {DEMO_REPO}")
    return DEMO_REPO


@pytest.fixture
def demo_sources(demo_repo: pathlib.Path) -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(demo_repo.glob("*.py"))
    }


@pytest.fixture(scope="session")
def snapshot(demo_repo: pathlib.Path):
    """Indexed demo repository. Session-scoped: indexing is not free."""
    from app.services.repository import build_snapshot

    return build_snapshot(demo_repo)


@pytest.fixture
async def db_session(tmp_path, monkeypatch) -> AsyncGenerator:
    """An isolated database per test, with the schema created."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.core.database import Base
    import app.models  # noqa: F401  (registers mappers)

    db_path = tmp_path / "test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


@pytest.fixture
async def api_client(tmp_path, monkeypatch) -> AsyncGenerator:
    """
    An HTTP client bound to the real ASGI app, with lifespan run.

    ``httpx.ASGITransport`` does not run startup/shutdown hooks, so the app's
    lifespan is entered manually to get a real schema and a clean scan registry.
    """
    from httpx import ASGITransport, AsyncClient

    monkeypatch.setenv("SENTINELFORGE_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path/'api.db'}")
    monkeypatch.setenv("SENTINELFORGE_DATA_DIRNAME", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINELFORGE_LOG_LEVEL", "WARNING")

    # Settings are cached at import time; rebuild them for this test.
    import app.core.config as config
    import app.core.database as database

    config.settings = config.Settings()
    database.settings = config.settings
    database.engine = database._build_engine()
    database.async_session.configure(bind=database.engine)

    from app.api.app import create_app
    from app.services import scan_manager

    scan_manager.manager = scan_manager.ScanManager()

    app = create_app()
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            client.app = app  # type: ignore[attr-defined]
            yield client


@pytest.fixture
def no_secrets(monkeypatch) -> None:
    """Fail loudly if a test ever depends on real credentials being present."""
    for name in ("IBM_WATSONX_API_KEY", "IBM_WATSONX_PROJECT_ID"):
        monkeypatch.delenv(name, raising=False)
