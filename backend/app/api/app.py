"""
FastAPI application factory.

Wires the routers, the database lifecycle, CORS and the scan registry. Kept as
a factory (``create_app``) rather than a module-level singleton so tests can
build an isolated app with its own settings and database.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core import config
from app.core.database import close_db, init_db
from app.core.logging_config import get_logger, setup_logging
from app.schemas.api import HealthOut
from app.services import scan_manager

logger = get_logger(__name__)

API_PREFIX = "/api"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    setup_logging(config.settings.log_level)
    config.settings.data_dir.mkdir(parents=True, exist_ok=True)
    await init_db()
    logger.info(
        "%s %s ready (provider=%s, sandbox=%s)",
        config.settings.app_name,
        config.settings.app_version,
        config.settings.ai_provider,
        config.settings.sandbox_backend,
    )
    try:
        yield
    finally:
        # Never leave a scan running against a half-torn-down process.
        await scan_manager.manager.shutdown()
        await close_db()


def create_app() -> FastAPI:
    app = FastAPI(
        title=config.settings.app_name,
        version=config.settings.app_version,
        description=(
            "Repository analysis, agent-driven triage, and sandbox-verified fixes. "
            "A fix is only reported as verified when an exploit reproduced the "
            "defect, the patch applied, the test suite stayed green and a rescan "
            "came back clean."
        ),
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
    )

    from app.api.routes import github, projects, scans, uploads

    app.include_router(projects.router, prefix=API_PREFIX)
    app.include_router(scans.router, prefix=API_PREFIX)
    app.include_router(uploads.router, prefix=API_PREFIX)
    app.include_router(github.router, prefix=API_PREFIX)

    @app.get(f"{API_PREFIX}/health", response_model=HealthOut, tags=["system"])
    async def health() -> HealthOut:
        """Liveness plus the operational facts an operator needs up front."""
        from sqlalchemy import text

        from app.core.database import session_scope

        database = "unknown"
        with contextlib.suppress(Exception):
            async with session_scope() as session:
                await session.execute(text("SELECT 1"))
                database = "ok"

        return HealthOut(
            status="ok",
            version=config.settings.app_version,
            provider=config.settings.ai_provider,
            database=database,
            sandbox=config.settings.sandbox_backend,
            running_scans=len(scan_manager.manager.list_running()),
        )

    @app.get("/health", include_in_schema=False)
    async def health_root() -> JSONResponse:
        """Unversioned health check for container orchestration."""
        return JSONResponse({"status": "ok", "version": config.settings.app_version})

    @app.exception_handler(ValueError)
    async def value_error_handler(_: Request, exc: ValueError) -> JSONResponse:
        """Surface bad input as 400 rather than an opaque 500."""
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)}
        )

    return app


app = create_app()

__all__ = ["app", "create_app"]
