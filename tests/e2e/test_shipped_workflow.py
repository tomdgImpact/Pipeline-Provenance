"""The workflow this project ships, asserted as an artifact consumers adopt.

What is asserted here is ordering and shape, which is where the shipped
workflow's guarantees actually live: the gate runs in a job of its own before
the build job exists, and the egress policy is the first step of every job.

What is **not** asserted here is runtime behaviour on a GitHub runner. That
cannot be established from a laptop, and pretending otherwise would be exactly
the overclaim this project exists to argue against. Runtime behaviour is
exercised by the demonstration workflow in CI (T031-T033).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "hardened-build.yml"
ACTIONS = REPO_ROOT / ".github" / "actions"

_YAML = YAML(typ="safe", pure=True)


@pytest.fixture(scope="module")
def workflow() -> dict[str, Any]:
    return dict(_YAML.load(WORKFLOW.read_text()))


@pytest.fixture(scope="module")
def jobs(workflow: dict[str, Any]) -> dict[str, Any]:
    return dict(workflow["jobs"])


class TestGateOrdering:
    def test_the_gate_is_a_job_of_its_own(self, jobs: dict[str, Any]) -> None:
        """A gate sharing a job with the build cannot constrain it: by the time
        it runs, the build's own steps are already scheduled behind it in the
        same untrusted context."""
        assert "policy-gate" in jobs

    def test_the_build_does_not_start_unless_the_gate_passed(
        self, jobs: dict[str, Any]
    ) -> None:
        assert jobs["build"]["needs"] == ["policy-gate"]

    def test_attestation_does_not_start_unless_the_build_finished(
        self, jobs: dict[str, Any]
    ) -> None:
        assert jobs["attest"]["needs"] == ["build"]

    def test_the_gate_job_runs_no_third_party_action_before_the_gate(
        self, jobs: dict[str, Any]
    ) -> None:
        """Everything in the gate job before `policy-gate` must be ours."""
        steps = jobs["policy-gate"]["steps"]
        index = next(
            i for i, step in enumerate(steps) if "policy-gate" in step.get("uses", "")
        )
        earlier = [step.get("uses", "") for step in steps[:index]]
        assert all(
            reference.startswith("./") or reference.startswith("actions/checkout@")
            for reference in earlier
        ), earlier


class TestEgress:
    @pytest.mark.parametrize("job", ["policy-gate", "build", "attest"])
    def test_the_egress_guard_is_the_first_step(
        self, jobs: dict[str, Any], job: str
    ) -> None:
        """Anything before it runs unrestricted, and that window is the finding."""
        assert jobs[job]["steps"][0]["uses"] == "./.github/actions/egress-guard"

    def test_the_guard_blocks_rather_than_audits_by_default(self) -> None:
        action = _YAML.load((ACTIONS / "egress-guard" / "action.yml").read_text())
        assert action["inputs"]["mode"]["default"] == "block"

    def test_the_allowlist_is_required_with_no_default(self) -> None:
        """A default allowlist would be a wildcard nobody chose."""
        action = _YAML.load((ACTIONS / "egress-guard" / "action.yml").read_text())
        assert action["inputs"]["allowed-endpoints"]["required"] is True
        assert "default" not in action["inputs"]["allowed-endpoints"]


class TestLeastPrivilege:
    def test_the_workflow_denies_by_default(self, workflow: dict[str, Any]) -> None:
        assert workflow["permissions"] == {}

    def test_the_gate_job_holds_no_write_scope(self, jobs: dict[str, Any]) -> None:
        assert jobs["policy-gate"]["permissions"] == {"contents": "read"}

    def test_the_build_job_holds_no_write_scope_at_all(
        self, jobs: dict[str, Any]
    ) -> None:
        """It runs caller-supplied code, so it gets nothing."""
        permissions = jobs["build"]["permissions"]
        writes = {scope for scope, level in permissions.items() if level == "write"}
        assert writes == set()

    def test_the_attest_job_holds_only_the_signing_scopes(
        self, jobs: dict[str, Any]
    ) -> None:
        permissions = jobs["attest"]["permissions"]
        writes = {scope for scope, level in permissions.items() if level == "write"}
        assert writes == {"id-token", "attestations"}

    def test_no_job_both_runs_caller_code_and_can_sign(
        self, jobs: dict[str, Any]
    ) -> None:
        """The property the split exists to establish.

        GitHub exposes ACTIONS_ID_TOKEN_REQUEST_TOKEN to every step of a job
        holding `id-token: write`. A job that also runs caller-supplied code
        lets that code mint an attestation under this workflow's identity —
        a valid signature over an artifact nobody here built. Threat model
        T-13, reachable without compromising anything.
        """
        offenders = []
        for name, job in jobs.items():
            writes = {
                scope
                for scope, level in (job.get("permissions") or {}).items()
                if level == "write"
            }
            if not writes & {"id-token", "attestations"}:
                continue
            for step in job.get("steps") or []:
                if "inputs." in str(step.get("run", "")):
                    offenders.append(f"{name}: {step.get('name', 'unnamed step')}")
        assert not offenders, (
            "job holds a signing scope and runs caller-supplied code:\n  "
            + "\n  ".join(offenders)
        )

    @pytest.mark.parametrize("job", ["policy-gate", "build"])
    def test_checkout_does_not_persist_credentials(
        self, jobs: dict[str, Any], job: str
    ) -> None:
        checkout = next(
            step
            for step in jobs[job]["steps"]
            if step.get("uses", "").startswith("actions/checkout@")
        )
        assert checkout["with"]["persist-credentials"] is False


class TestAttestation:
    def test_both_documents_are_emitted(self, jobs: dict[str, Any]) -> None:
        uses = [step.get("uses", "") for step in jobs["attest"]["steps"]]
        assert any("anchore/sbom-action" in reference for reference in uses)
        assert any("attest-build-provenance" in reference for reference in uses)

    def test_the_build_fails_if_one_document_is_missing(
        self, jobs: dict[str, Any]
    ) -> None:
        """The attestation set is atomic; half of it is not a weaker guarantee,
        it is a different and useless one."""
        scripts = [step.get("run", "") for step in jobs["attest"]["steps"]]
        assert any(
            "sbom.cdx.json" in script and "exit 1" in script for script in scripts
        )


class TestGateDefaults:
    def test_unverified_checks_are_not_permitted_by_default(self) -> None:
        action = _YAML.load((ACTIONS / "policy-gate" / "action.yml").read_text())
        assert action["inputs"]["allow-unverified"]["default"] == "false"

    def test_the_default_threshold_is_the_lowest(self) -> None:
        action = _YAML.load((ACTIONS / "policy-gate" / "action.yml").read_text())
        assert action["inputs"]["fail-on"]["default"] == "low"


def test_the_migration_path_is_documented() -> None:
    """A control nobody can adopt is a control nobody has."""
    migration = (REPO_ROOT / "docs" / "MIGRATION.md").read_text()
    assert "hardened-build.yml" in migration
    assert "egress-guard" in migration
    assert "policy-gate" in migration
