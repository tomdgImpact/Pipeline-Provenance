"""This repository's own dependencies, held to I1.

The audit tool checks that a repository's dependency manifests resolve with
hashes. These assert the same thing about us, from the other side: that the
lockfile exists, that it carries hashes, and that the gate reads it rather than
whatever happens to be installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.security


def test_a_lockfile_is_committed(repo_root: Path) -> None:
    """I1 for the Python side. Without it, "pinned with hashes" is a claim about
    other people's repositories only."""
    assert (repo_root / "uv.lock").is_file()


def test_the_lockfile_carries_hashes(repo_root: Path) -> None:
    text = (repo_root / "uv.lock").read_text()
    assert "hash = " in text or "sha256" in text


def test_the_audit_gate_reads_the_lockfile_not_the_environment(
    repo_root: Path,
) -> None:
    """Auditing the installed environment audits whatever happened to be
    present, including this project, which has no published record."""
    workflow = (repo_root / ".github" / "workflows" / "ci.yml").read_text()
    assert "uv export --no-emit-project" in workflow
    assert (
        "pip-audit --strict --progress-spinner=off -r requirements.audit.txt"
        in workflow
    )


def test_the_exported_requirements_file_is_never_committed(repo_root: Path) -> None:
    ignore = (repo_root / ".gitignore").read_text()
    assert "requirements.audit.txt" in ignore
    assert not (repo_root / "requirements.audit.txt").is_file()
