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
import pytest_asyncio

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


@pytest.fixture(autouse=True, scope="session")
def isolated_runtime(tmp_path_factory):
    """
    Keep every test's runtime state out of the repository.

    Without this, the API tests extract uploaded archives into
    ``data/workspaces/`` inside the checkout, because a dozen application
    modules do ``from app.core.config import settings`` at import time and so
    captured whatever Settings existed then. The result was 99 stale copies of
    the demo repository accumulating in the working tree between runs.

    So: point the environment at a temporary data directory, rebuild Settings,
    and rebind it on every already-imported module. One Settings instance per
    process is still the right production behaviour -- the problem is only that
    tests need to *replace* it.
    """
    import app.core.config as config

    root = tmp_path_factory.mktemp("sentinelforge-runtime")
    os.environ["SENTINELFORGE_DATA_DIRNAME"] = str(root / "data")
    os.environ["SENTINELFORGE_DATABASE_URL"] = f"sqlite+aiosqlite:///{root / 'default.db'}"
    os.environ["SENTINELFORGE_LOG_LEVEL"] = "WARNING"

    fresh = config.Settings()
    config.settings = fresh
    for module in list(sys.modules.values()):
        if module is None:
            continue
        if isinstance(getattr(module, "settings", None), config.Settings):
            module.settings = fresh

    (root / "data").mkdir(parents=True, exist_ok=True)
    yield root
    os.environ.pop("SENTINELFORGE_DATA_DIRNAME", None)
    os.environ.pop("SENTINELFORGE_DATABASE_URL", None)


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


@pytest.fixture(scope="session")
def scan_run(demo_repo: pathlib.Path, python_executable: str):
    """
    One real end-to-end scan of the demo repository, with its event timeline.

    Session-scoped and synchronous: the orchestrator is fully async, so driving
    it here with ``asyncio.run`` gives every test module a completed, verified
    scan to assert against without paying for a fresh run each time. The events
    are captured here because the orchestrator publishes them through a callback
    rather than returning them.
    """
    import asyncio
    from types import SimpleNamespace

    from app.services.orchestrator import ScanOrchestrator

    events: list[dict] = []

    async def _run():
        return await ScanOrchestrator(on_progress=events.append).run(
            demo_repo, project_id="demo", python=python_executable
        )

    return SimpleNamespace(outcome=asyncio.run(_run()), events=events)


@pytest_asyncio.fixture
async def outcome(scan_run):
    """The shared scan outcome."""
    return scan_run.outcome


@pytest.fixture
def scan_events(scan_run) -> list[dict]:
    """The progress events published during the shared scan."""
    return scan_run.events


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
async def api_client(tmp_path) -> AsyncGenerator:
    """
    An HTTP client bound to the real ASGI app, with lifespan run.

    ``httpx.ASGITransport`` does not run startup/shutdown hooks, so the app's
    lifespan is entered manually to get a real schema and a clean scan registry.

    Runtime paths are already redirected by the session-scoped
    ``isolated_runtime`` fixture; only the database engine is per-test.
    """
    from httpx import ASGITransport, AsyncClient

    import app.core.config as config
    import app.core.database as database

    # Same runtime paths as the session fixture, plus a per-test database.
    database.settings = config.Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
    )
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
