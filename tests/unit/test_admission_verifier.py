"""The only place in this project where a decision is made.

Every test here asserts a refusal path. That asymmetry is the design: accept is
one narrow case, and everything else — including every error — is refuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from pipeline_provenance.attest import provenance, sbom
from pipeline_provenance.attest.verify import (
    CosignVerifier,
    Policy,
    load_attestation,
    verify,
)
from pipeline_provenance.model import AttestationSet

IDENTITY = "https://github.com/tomdgImpact/Pipeline-Provenance/.github/workflows/hardened-build.yml@refs/tags/v0.1.0"
STAMP = "2026-08-20T00:00:00Z"


@dataclass(frozen=True)
class FakeVerifier:
    """A signature backend under the test's control."""

    name: str = "fake"
    is_available: bool = True
    accepts: bool = True
    detail: str = "fake backend"

    def available(self) -> tuple[bool, str]:
        return self.is_available, self.detail

    def verify(self, subject: Path, identity: str, issuer: str) -> tuple[bool, str]:
        del subject, issuer  # a fake backend inspects neither
        return self.accepts, f"{self.name}: {identity}"


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    path = tmp_path / "app.whl"
    path.write_bytes(b"payload")
    return path


def _attestation(
    artifact: Path, *, builder: str = IDENTITY, **overrides: object
) -> AttestationSet:
    subjects = provenance.subjects([artifact], relative_to=artifact.parent)
    statement = provenance.statement(
        subjects=subjects,
        builder_id=builder,
        source_uri="git+https://github.com/tomdgImpact/Pipeline-Provenance",
        source_digest="b" * 40,
        invocation_id="run-1",
        started_on=STAMP,
        finished_on=STAMP,
    )
    document = sbom.document(
        subjects=subjects,
        serial_number="urn:uuid:1",
        timestamp=STAMP,
        components=tuple(overrides.get("components", ())),  # type: ignore[arg-type]
    )
    return AttestationSet(subjects=subjects, provenance=statement, sbom=document)


class TestNoPermissiveDefault:
    def test_an_unset_identity_refuses_before_anything_else_runs(
        self, artifact: Path
    ) -> None:
        decision = verify(
            artifact,
            _attestation(artifact),
            Policy(expected_identity=""),
            FakeVerifier(),
        )
        assert decision.accepted is False
        assert "no expected signer identity" in decision.reason
        assert [name for name, _, _ in decision.checks] == [
            "expected-identity-configured"
        ]


class TestCannotVerifyMeansRefuse:
    def test_an_unavailable_backend_refuses(self, artifact: Path) -> None:
        """Not "accept, could not check". A backend that quietly does nothing
        when it is missing is the failure this project exists to argue against."""
        decision = verify(
            artifact,
            _attestation(artifact),
            Policy(expected_identity=IDENTITY),
            FakeVerifier(is_available=False, detail="cosign is not installed"),
        )
        assert decision.accepted is False
        assert "cannot verify the signature" in decision.reason

    def test_a_failing_signature_refuses(self, artifact: Path) -> None:
        decision = verify(
            artifact,
            _attestation(artifact),
            Policy(expected_identity=IDENTITY),
            FakeVerifier(accepts=False),
        )
        assert decision.accepted is False
        assert "signature verification failed" in decision.reason


class TestSubjectBinding:
    def test_an_artifact_absent_from_the_subject_list_refuses(
        self, artifact: Path, tmp_path: Path
    ) -> None:
        """A valid attestation for a different artifact is a valid attestation."""
        other = tmp_path / "other.whl"
        other.write_bytes(b"different payload")
        decision = verify(
            other,
            _attestation(artifact),
            Policy(expected_identity=IDENTITY),
            FakeVerifier(),
        )
        assert decision.accepted is False
        assert "does not cover this artifact" in decision.reason

    def test_a_missing_subject_file_refuses(
        self, tmp_path: Path, artifact: Path
    ) -> None:
        decision = verify(
            tmp_path / "absent.whl",
            _attestation(artifact),
            Policy(expected_identity=IDENTITY),
            FakeVerifier(),
        )
        assert decision.accepted is False
        assert "subject not found" in decision.reason


class TestIdentity:
    def test_a_valid_signature_from_the_wrong_builder_refuses(
        self, artifact: Path
    ) -> None:
        """T-13. The signature can be perfectly valid and still be the wrong
        signature."""
        decision = verify(
            artifact,
            _attestation(artifact, builder="https://example.invalid/other/workflow"),
            Policy(expected_identity=IDENTITY),
            FakeVerifier(),
        )
        assert decision.accepted is False
        assert "unexpected identity" in decision.reason

    def test_provenance_with_no_builder_refuses(self, artifact: Path) -> None:
        attestation = _attestation(artifact)
        broken = AttestationSet(
            subjects=attestation.subjects,
            provenance={"predicate": {"runDetails": {}}},
            sbom=attestation.sbom,
        )
        decision = verify(
            artifact, broken, Policy(expected_identity=IDENTITY), FakeVerifier()
        )
        assert decision.accepted is False


class TestSbomPolicy:
    def test_a_denied_component_refuses(self, artifact: Path) -> None:
        attestation = _attestation(
            artifact, components=({"type": "library", "name": "left-pad"},)
        )
        decision = verify(
            artifact,
            attestation,
            Policy(expected_identity=IDENTITY, denied_components=("left-pad",)),
            FakeVerifier(),
        )
        assert decision.accepted is False
        assert "denied components" in decision.reason

    def test_requiring_an_inventory_refuses_an_empty_one(self, artifact: Path) -> None:
        """This generator does not resolve components. A policy that needs them
        must say so and be refused rather than silently satisfied by nothing."""
        decision = verify(
            artifact,
            _attestation(artifact),
            Policy(expected_identity=IDENTITY, require_sbom_components=True),
            FakeVerifier(),
        )
        assert decision.accepted is False
        assert "component inventory" in decision.reason


class TestAccept:
    def test_a_complete_valid_set_is_accepted(self, artifact: Path) -> None:
        decision = verify(
            artifact,
            _attestation(artifact),
            Policy(expected_identity=IDENTITY),
            FakeVerifier(),
        )
        assert decision.accepted is True
        assert decision.asserted_identity == IDENTITY

    def test_the_decision_records_every_check_that_ran(self, artifact: Path) -> None:
        """An operator must be able to reconstruct why something was let in
        without re-running anything."""
        decision = verify(
            artifact,
            _attestation(artifact),
            Policy(expected_identity=IDENTITY),
            FakeVerifier(),
        )
        names = [name for name, _, _ in decision.checks]
        assert names == [
            "expected-identity-configured",
            "subject-present",
            "subject-digest-matches",
            "signature-backend-available",
            "signature-verified",
            "builder-identity-matches",
            "sbom-policy",
        ]
        assert all(passed for _, passed, _ in decision.checks)


class TestLoading:
    def test_a_missing_sbom_refuses_the_whole_set(self, tmp_path: Path) -> None:
        statement = tmp_path / "provenance.json"
        statement.write_text('{"subject": [{"name": "a", "digest": {"sha256": "aa"}}]}')
        with pytest.raises(ValueError, match="atomic"):
            load_attestation(statement, tmp_path / "absent.json")

    def test_malformed_json_refuses(self, tmp_path: Path) -> None:
        statement = tmp_path / "provenance.json"
        statement.write_text("{not json")
        (tmp_path / "sbom.json").write_text("{}")
        with pytest.raises(ValueError, match="not valid JSON"):
            load_attestation(statement, tmp_path / "sbom.json")

    def test_provenance_with_no_subject_refuses(self, tmp_path: Path) -> None:
        statement = tmp_path / "provenance.json"
        statement.write_text('{"subject": []}')
        (tmp_path / "sbom.json").write_text("{}")
        with pytest.raises(ValueError, match="attests to nothing"):
            load_attestation(statement, tmp_path / "sbom.json")


class TestCosignBackend:
    def test_a_missing_binary_is_reported_unavailable_not_skipped(self) -> None:
        backend = CosignVerifier(binary="definitely-not-a-real-binary-name")
        available, detail = backend.available()
        assert available is False
        assert "not installed" in detail
