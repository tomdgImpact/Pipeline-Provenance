"""Shared fixtures.

Everything here is offline. A test that needs the network is either an
end-to-end test against a local fixture or it does not belong in this suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """The repository under test — this repository."""
    return REPO_ROOT


@pytest.fixture(scope="session")
def workflow_files(repo_root: Path) -> list[Path]:
    """Every workflow definition this repository ships."""
    return sorted((repo_root / ".github" / "workflows").glob("*.yml"))
