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


def test_verify_refuses_without_the_documents_it_needs() -> None:
    """`verify` never runs on a partial input. The attestation set is atomic,
    and a verifier that accepts half of one accepts anything."""
    result = CliRunner().invoke(main, ["verify"])
    assert result.exit_code != 0


def test_verify_refuses_with_no_expected_identity(tmp_path: Path) -> None:
    """An identity that defaults to "any" turns verification into decoration."""
    from pipeline_provenance.attest.verify import Policy, verify

    artifact = tmp_path / "app.whl"
    artifact.write_bytes(b"payload")
    from pipeline_provenance.model import AttestationSet, Subject

    attestation = AttestationSet(
        subjects=(Subject(name="app.whl", sha256="a" * 64),),
        provenance={"predicate": {}},
        sbom={"bomFormat": "CycloneDX"},
    )
    decision = verify(artifact, attestation, Policy(expected_identity=""))
    assert decision.accepted is False
    assert "no expected signer identity" in decision.reason


def test_doctor_does_not_claim_an_unavailable_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no token configured, remote resolution must report UNAVAILABLE."""
    monkeypatch.delenv("PPV_GITHUB_TOKEN", raising=False)
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code == 0
    line = next(row for row in result.output.splitlines() if "remote reference" in row)
    assert "UNAVAILABLE" in line
