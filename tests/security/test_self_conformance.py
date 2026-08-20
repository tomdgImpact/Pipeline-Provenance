"""This repository must satisfy the invariants it sells.

A supply-chain hardening project whose own pipeline runs unpinned third-party
code is an argument against itself. These assertions run against the workflow
files this repository actually ships, not against fixtures.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

from pipeline_provenance.audit import audit
from pipeline_provenance.model import Assessment, Status

pytestmark = pytest.mark.security

# A pinned reference is `owner/repo@<40 hex>` or `owner/repo/path@<40 hex>`.
_YAML = YAML(typ="safe", pure=True)


def _load(path: Path) -> Any:
    """Load with the parser this project actually depends on.

    An ambient parser that happens to be installed is an undeclared
    dependency, which is the class of problem this repository is about.
    """
    return _YAML.load(path.read_text())


PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
# Local composite actions and Docker references are handled separately.
LOCAL = re.compile(r"^(\./|docker://)")


def _jobs(path: Path) -> dict[str, Any]:
    document = _load(path)
    jobs = document.get("jobs", {})
    assert isinstance(jobs, dict)
    return jobs


def _uses(path: Path) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for name, job in _jobs(path).items():
        for step in job.get("steps", []) or []:
            reference = step.get("uses")
            if reference:
                found.append((name, reference))
    return found


def test_workflows_exist(workflow_files: list[Path]) -> None:
    """Guard against the suite passing because it found nothing to check."""
    assert workflow_files, "no workflow files found; this suite would pass vacuously"


def test_every_action_is_pinned_to_a_digest(workflow_files: list[Path]) -> None:
    """I1 — nothing runs unpinned.

    A tag is a mutable pointer. Pinning to a commit SHA is what makes the code
    reviewed at merge time the code executed at run time.
    """
    unpinned = [
        f"{path.name}:{job} -> {reference}"
        for path in workflow_files
        for job, reference in _uses(path)
        if not LOCAL.match(reference) and not PINNED.match(reference)
    ]
    assert not unpinned, "unpinned action references:\n  " + "\n  ".join(unpinned)


def test_every_pinned_action_carries_a_version_comment(
    workflow_files: list[Path],
) -> None:
    """A digest is unreadable to a reviewer without the version beside it.

    The comment is ours and cannot be repointed by the publisher, so it costs
    nothing in integrity and buys back the readability that pinning removes.
    """
    missing: list[str] = []
    for path in workflow_files:
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("- uses:", "uses:")) and "@" in stripped:
                if "./" in stripped:
                    continue
                if "#" not in stripped:
                    missing.append(f"{path.name}:{number}: {stripped}")
    assert not missing, "pinned action without a version comment:\n  " + "\n  ".join(
        missing
    )


def test_top_level_permissions_deny_by_default(workflow_files: list[Path]) -> None:
    """I2 — no workflow inherits the repository default token scope."""
    for path in workflow_files:
        document = _load(path)
        assert "permissions" in document, f"{path.name}: no top-level permissions block"
        assert document["permissions"] in ({}, None), (
            f"{path.name}: top-level permissions must deny by default; "
            f"got {document['permissions']!r}"
        )


def test_every_job_declares_its_own_permissions(workflow_files: list[Path]) -> None:
    """I2 — least privilege is declared per job, never inherited silently."""
    undeclared = [
        f"{path.name}:{name}"
        for path in workflow_files
        for name, job in _jobs(path).items()
        if "permissions" not in job
    ]
    assert not undeclared, "job without an explicit permissions block:\n  " + (
        "\n  ".join(undeclared)
    )


def test_no_job_requests_write_scope_it_does_not_need(
    workflow_files: list[Path],
) -> None:
    """I2 — write scope is an exception that has to be argued for.

    `security-events: write` is expected on the SAST job, which uploads SARIF.
    Anything else with write scope is a finding.
    """
    # id-token and attestations mint a short-lived signing identity and cannot
    # modify the repository, so they are not repository write scope. The SAST
    # job's security-events: write is argued in docs/THREAT_MODEL.md section 9.
    attestation_scopes = {"id-token", "attestations"}
    allowed = {("ci.yml", "sast", "security-events")}
    offenders: list[str] = []
    for path in workflow_files:
        for name, job in _jobs(path).items():
            permissions = job.get("permissions") or {}
            if not isinstance(permissions, dict):
                continue
            for scope, level in permissions.items():
                if (
                    level == "write"
                    and scope not in attestation_scopes
                    and (path.name, name, scope) not in allowed
                ):
                    offenders.append(f"{path.name}:{name}: {scope}: write")
    assert not offenders, "unexpected write scope:\n  " + "\n  ".join(offenders)


def test_no_privileged_trigger_on_untrusted_forks(workflow_files: list[Path]) -> None:
    """Threat model T-10 — pull_request_target hands write scope to fork code."""
    for path in workflow_files:
        document = _load(path)
        triggers = document.get(True, document.get("on"))
        assert triggers is not None, f"{path.name}: no trigger block"
        names = triggers if isinstance(triggers, dict) else {triggers: None}
        assert "pull_request_target" not in names, (
            f"{path.name}: pull_request_target is not permitted without an "
            "annotated review (threat model T-10)"
        )


def test_checkout_does_not_persist_credentials(workflow_files: list[Path]) -> None:
    """A persisted token stays in the runner's git config for later steps.

    Every third-party step after checkout can read it, which is exactly the
    adversary in the threat model (T-01).
    """
    offenders: list[str] = []
    for path in workflow_files:
        for name, job in _jobs(path).items():
            for step in job.get("steps", []) or []:
                reference = step.get("uses", "")
                if reference.startswith("actions/checkout@"):
                    with_block = step.get("with") or {}
                    if with_block.get("persist-credentials") is not False:
                        offenders.append(f"{path.name}:{name}")
    assert not offenders, "checkout persists credentials in:\n  " + "\n  ".join(
        offenders
    )


def test_every_job_has_a_timeout(workflow_files: list[Path]) -> None:
    """An unbounded job is a denial-of-wallet surface and a stuck queue."""
    missing = [
        f"{path.name}:{name}"
        for path in workflow_files
        for name, job in _jobs(path).items()
        if "timeout-minutes" not in job
    ]
    assert not missing, "job without timeout-minutes:\n  " + "\n  ".join(missing)


class TestSelfAudit:
    """Run the shipped tool against the repository that ships it.

    This is the strongest self-conformance test available: it exercises the
    real rule set rather than a re-implementation of it, so a rule that stops
    working fails here too.
    """

    ACCEPTED: frozenset[tuple[str, str]] = frozenset(
        {
            # The SAST job uploads SARIF to code scanning, which needs
            # `security-events: write`. The rule is right that write scope has
            # to be argued for; this is the argument, recorded in
            # docs/THREAT_MODEL.md section 9 as accepted residual risk. It is
            # listed here so the exception is explicit rather than suppressed.
            ("I2/excessive-permission", "sast"),
        }
    )

    def test_no_confirmed_violation_beyond_the_argued_exception(
        self, repo_root: Path
    ) -> None:
        result = audit(repo_root, generated_at="1970-01-01T00:00:00Z")
        unexpected = [
            f
            for f in result.verified_findings
            if not any(f.rule_id == rule for rule, _ in self.ACCEPTED)
        ]
        assert not unexpected, "unaccepted findings against this repository:\n  " + (
            "\n  ".join(f"{f.rule_id} at {f.location}" for f in unexpected)
        )

    def test_every_unverified_finding_is_explained_in_the_caveats(
        self, repo_root: Path
    ) -> None:
        """An unverified finding is not a violation, and it is not a pass
        either. It has to reach a reader who only skims, so the caveat list
        must say why the check did not complete."""
        result = audit(repo_root, generated_at="1970-01-01T00:00:00Z")
        unverified = [
            f for f in result.findings if f.assessment is Assessment.UNVERIFIED
        ]
        for finding in unverified:
            assert any(
                finding.invariant.value in statement
                for statement in result.unverifiable
            ), f"{finding.rule_id} is unverified but no caveat says why"

    def test_the_accepted_exception_still_exists(self, repo_root: Path) -> None:
        """If the exception is ever fixed, this fails and forces the list to
        shrink. An accepted-risk list that only grows is a suppression file."""
        result = audit(repo_root, generated_at="1970-01-01T00:00:00Z")
        reported = {f.rule_id for f in result.findings}
        for rule, _job in self.ACCEPTED:
            assert rule in reported, (
                f"{rule} is accepted in this list but no longer reported. "
                "Remove it from ACCEPTED."
            )

    def test_the_pinning_and_egress_invariants_hold(self, repo_root: Path) -> None:
        result = audit(repo_root, generated_at="1970-01-01T00:00:00Z")
        statuses = {r.invariant.value: r.status for r in result.invariants}
        assert statuses["I1"] is Status.PASSING
        assert statuses["I4"] is Status.PASSING

    def test_provenance_is_unverified_and_not_claimed(self, repo_root: Path) -> None:
        """This repository ships a build workflow and owns no admission point;
        its consumers do. The tool reports that as unverified, which is the
        honest answer and explicitly not a pass."""
        result = audit(repo_root, generated_at="1970-01-01T00:00:00Z")
        statuses = {r.invariant.value: r.status for r in result.invariants}
        assert statuses["I3"] is Status.UNVERIFIED
