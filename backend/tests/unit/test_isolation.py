"""
Guards against the test suite writing into the checkout.

Both tests here exist because of a real regression: 99 copies of the demo
repository were left in ``data/workspaces/`` and local sandbox runs staged code
in ``data/local-sandbox/`` inside the working tree, because paths were captured
from configuration at import time. They were gitignored, so nothing was ever
committed, but they made every leak scan noisy and hid real findings.
"""

from __future__ import annotations

import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]


def test_no_runtime_state_in_the_checkout(isolated_runtime) -> None:
    data_dir = REPO_ROOT / "data"
    stray = [p for p in data_dir.rglob("*") if p.is_file()] if data_dir.exists() else []
    assert stray == [], f"tests wrote into the checkout: {[str(p) for p in stray[:5]]}"


def test_sandbox_root_follows_configuration(isolated_runtime) -> None:
    """The staging root must track the configured data dir, not import-time state."""
    from app.core import config
    from app.sandbox.local import local_root

    assert local_root() == config.settings.data_dir / "local-sandbox"
    assert REPO_ROOT not in local_root().parents, "sandbox would stage code in the checkout"


def test_workspaces_land_under_the_configured_data_dir(isolated_runtime) -> None:
    from app.core import config
    from app.services.repository import workspace_for

    project_id = "abc123"
    path = workspace_for(project_id)
    assert config.settings.data_dir in path.parents
    assert REPO_ROOT not in path.parents
