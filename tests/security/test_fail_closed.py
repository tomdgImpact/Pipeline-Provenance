"""Fail-closed properties of the tool itself.

These assert the absence of a permissive path, which is a stronger statement
than asserting that the strict path works.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from pipeline_provenance.cli import main

pytestmark = pytest.mark.security


def test_verifier_identity_has_no_default(repo_root: Path) -> None:
    """ADR-0002 — an expected identity that defaults to anything accepts
    everything, which turns verification into decoration."""
    for source in (repo_root / "src").rglob("*.py"):
        text = source.read_text()
        assert 'PPV_EXPECTED_SIGNER_IDENTITY", ' not in text, (
            f"{source}: expected signer identity must not have a default"
        )
        assert "PPV_EXPECTED_SIGNER_IDENTITY', " not in text, (
            f"{source}: expected signer identity must not have a default"
        )


def test_unimplemented_commands_are_absent_rather_than_empty() -> None:
    """An unimplemented command that returns an empty result is read by the
    caller as a clean result. Absence forces the caller to notice."""
    runner = CliRunner()
    for command in ("audit", "verify"):
        result = runner.invoke(main, [command])
        assert result.exit_code != 0
        assert "No such command" in result.output


def test_doctor_does_not_claim_an_unavailable_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no token configured, remote resolution must report UNAVAILABLE."""
    monkeypatch.delenv("PPV_GITHUB_TOKEN", raising=False)
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code == 0
    line = next(row for row in result.output.splitlines() if "remote reference" in row)
    assert "UNAVAILABLE" in line
