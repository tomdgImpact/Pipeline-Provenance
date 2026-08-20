"""`ppv verify` through the real process, including the refusal paths.

The e2e suite matters more here than anywhere else: the refusals must hold when
the command is invoked by a deployment system that only sees an exit code.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pipeline_provenance.attest import provenance, sbom

REPO_ROOT = Path(__file__).resolve().parents[2]
IDENTITY = "https://github.com/tomdgImpact/Pipeline-Provenance/.github/workflows/hardened-build.yml@refs/tags/v0.1.0"
STAMP = "2026-08-20T00:00:00Z"


def run_ppv(
    *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    import os

    environment = dict(os.environ)
    environment.pop("PPV_EXPECTED_SIGNER_IDENTITY", None)
    if env:
        environment.update(env)
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "pipeline_provenance.cli", *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=environment,
        check=False,
    )


@pytest.fixture
def bundle(tmp_path: Path) -> tuple[Path, Path, Path]:
    artifact = tmp_path / "app.whl"
    artifact.write_bytes(b"payload")
    subjects = provenance.subjects([artifact], relative_to=tmp_path)

    statement = tmp_path / "provenance.json"
    statement.write_text(
        json.dumps(
            provenance.statement(
                subjects=subjects,
                builder_id=IDENTITY,
                source_uri="git+https://github.com/tomdgImpact/Pipeline-Provenance",
                source_digest="b" * 40,
                invocation_id="run-1",
                started_on=STAMP,
                finished_on=STAMP,
            )
        )
    )
    document = tmp_path / "sbom.json"
    document.write_text(
        json.dumps(
            sbom.document(
                subjects=subjects, serial_number="urn:uuid:1", timestamp=STAMP
            )
        )
    )
    return artifact, statement, document


class TestRefusals:
    def test_no_expected_identity_refuses(
        self, bundle: tuple[Path, Path, Path]
    ) -> None:
        artifact, statement, document = bundle
        process = run_ppv(
            "verify",
            str(artifact),
            "--provenance",
            str(statement),
            "--sbom",
            str(document),
        )
        assert process.returncode != 0
        assert "REFUSE" in process.stdout
        assert "no expected signer identity" in process.stdout

    def test_a_missing_sbom_refuses_the_whole_set(
        self, bundle: tuple[Path, Path, Path], tmp_path: Path
    ) -> None:
        artifact, statement, _ = bundle
        process = run_ppv(
            "verify",
            str(artifact),
            "--provenance",
            str(statement),
            "--sbom",
            str(tmp_path / "absent.json"),
        )
        assert process.returncode != 0

    def test_the_signature_backend_being_absent_refuses(
        self, bundle: tuple[Path, Path, Path]
    ) -> None:
        """On a host with no cosign, verification refuses. It does not pass with
        a warning, which is the only outcome that would be worse than failing."""
        artifact, statement, document = bundle
        process = run_ppv(
            "verify",
            str(artifact),
            "--provenance",
            str(statement),
            "--sbom",
            str(document),
            "--expected-identity",
            IDENTITY,
        )
        assert process.returncode != 0
        assert "REFUSE" in process.stdout

    def test_an_artifact_outside_the_subject_list_refuses(
        self, bundle: tuple[Path, Path, Path], tmp_path: Path
    ) -> None:
        _, statement, document = bundle
        other = tmp_path / "other.whl"
        other.write_bytes(b"different")
        process = run_ppv(
            "verify",
            str(other),
            "--provenance",
            str(statement),
            "--sbom",
            str(document),
            "--expected-identity",
            IDENTITY,
        )
        assert process.returncode != 0
        assert "does not cover this artifact" in process.stdout


class TestIdentitySource:
    def test_the_environment_variable_is_read_when_the_flag_is_absent(
        self, bundle: tuple[Path, Path, Path]
    ) -> None:
        artifact, statement, document = bundle
        process = run_ppv(
            "verify",
            str(artifact),
            "--provenance",
            str(statement),
            "--sbom",
            str(document),
            env={"PPV_EXPECTED_SIGNER_IDENTITY": IDENTITY},
        )
        assert "no expected signer identity" not in process.stdout
        assert IDENTITY in process.stdout


class TestAdvisoryMode:
    def test_advisory_mode_is_labelled_and_does_not_gate(
        self, bundle: tuple[Path, Path, Path]
    ) -> None:
        """FR-020. Verification inside the build runs in the context it is
        checking, so it shortens the feedback loop and proves nothing."""
        artifact, statement, document = bundle
        process = run_ppv(
            "verify",
            str(artifact),
            "--provenance",
            str(statement),
            "--sbom",
            str(document),
            "--expected-identity",
            IDENTITY,
            "--advisory",
        )
        assert process.returncode == 0
        assert "ADVISORY" in process.stdout
        assert "proves nothing" in process.stdout


class TestTransparency:
    def test_every_check_that_ran_is_printed(
        self, bundle: tuple[Path, Path, Path]
    ) -> None:
        artifact, statement, document = bundle
        process = run_ppv(
            "verify",
            str(artifact),
            "--provenance",
            str(statement),
            "--sbom",
            str(document),
            "--expected-identity",
            IDENTITY,
        )
        assert "expected-identity-configured" in process.stdout
        assert "subject-digest-matches" in process.stdout
        assert "signature-backend-available" in process.stdout
