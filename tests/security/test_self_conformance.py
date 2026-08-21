"""This repository must satisfy the invariants it sells.

A supply-chain hardening project whose own pipeline runs unpinned third-party
code is an argument against itself. These assertions run against the workflow
files this repository actually ships, not against fixtures.
"""

from __future__ import annotations

import json
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


def _newest_record(repo_root: Path, family: str) -> dict[str, Any]:
    """The most recent published figure of a given family.

    Records are re-measured and re-dated rather than edited in place, so these
    tests must follow the newest one. Hardcoding a date is how a test keeps
    passing against a record the README no longer quotes — which is exactly the
    drift that shipped an out-of-date performance table at v0.1.0.
    """
    published = sorted(
        (repo_root / "benchmarks" / "published").glob(f"{family}-*.json")
    )
    assert published, f"no published {family} record"
    return dict(json.loads(published[-1].read_text()))


def _readme_table(readme: str, heading: str) -> list[list[str]]:
    """Rows of the first markdown table under ``heading``."""
    section = readme[readme.index(heading) :]
    rows: list[list[str]] = []
    for line in section.splitlines()[1:]:
        if line.startswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if not all(set(cell) <= set("-: ") for cell in cells):
                rows.append(cells)
        elif rows:
            break
    return rows[1:]


class TestPublishedClaims:
    """Every number in the README must be re-derivable from the harness.

    A figure a reader cannot reproduce is a figure they have to take on trust,
    and this project asks for less trust than that.
    """

    @pytest.fixture
    def readme(self, repo_root: Path) -> str:
        return (repo_root / "README.md").read_text()

    def test_the_detection_figures_match_the_published_record(
        self, repo_root: Path, readme: str
    ) -> None:
        published = _newest_record(repo_root, "detection")
        assert published["sc_001_detection"]["precision"] == 1.0
        assert published["sc_001_detection"]["recall"] == 1.0
        declared = published["corpus"]["declared_defects"]
        assert f"{declared} declared defects" in readme

    def test_the_distribution_figures_match_the_published_record(
        self, repo_root: Path, readme: str
    ) -> None:
        published = _newest_record(repo_root, "distribution")
        assert published["sample"]["workflow_files"] == 101
        assert "101 workflow files" in readme.replace("\n", " ")

    def test_every_performance_row_matches_the_published_record(
        self, repo_root: Path, readme: str
    ) -> None:
        """The one that was missing.

        The detection figures had a test binding them to the record; the
        performance table did not, so it quoted a run from before the release
        while the committed record held another. Every cell is now compared,
        not just the headline.
        """
        published = _newest_record(repo_root, "performance")
        measurements = {m["target"]: m for m in published["measurements"]}
        labels = {
            "This repository": "Pipeline-Provenance",
            "`monorepo` fixture": "monorepo",
            "`naive` fixture": "naive",
        }

        rows = _readme_table(readme, "### Audit performance")
        assert rows, "no performance table found in the README"

        for target, workflows, median, p95 in rows:
            measured = measurements[labels[target]]
            assert int(workflows) == measured["workflows"], target
            assert str(measured["median_ms"]) in median, target
            assert str(measured["p95_ms"]) in p95, target

    def test_the_performance_table_names_the_machine_it_ran_on(
        self, repo_root: Path, readme: str
    ) -> None:
        """A timing without its hardware is one nobody can reproduce."""
        published = _newest_record(repo_root, "performance")
        assert published["machine"]["platform"] in readme

    def test_every_published_number_names_its_date(self, readme: str) -> None:
        assert readme.count("measured 2026-08-2") >= 3

    def test_the_limitations_section_is_still_there(self, readme: str) -> None:
        """It is a mandatory deliverable, and the section most likely to be
        trimmed by someone tidying up before a launch."""
        assert "## Limitations" in readme
        assert "never that it is correct" in readme
        assert "no third-party review" in readme.lower()
