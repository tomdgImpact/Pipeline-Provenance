"""I4 — egress denied by default, and denied before anything else runs."""

from __future__ import annotations

from pathlib import Path

from pipeline_provenance.discovery import Repository, load_repository
from pipeline_provenance.model import Severity, Status
from pipeline_provenance.rules import i4_egress as i4

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"
HARDEN = "step-security/harden-runner@" + "0" * 40


def _rules(repository: Repository) -> list[str]:
    return sorted(f.rule_id for f in i4.evaluate(repository).findings)


def _fixture(name: str) -> Repository:
    return load_repository(FIXTURES / name)


def _repo(tmp_path: Path, body: str) -> Repository:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "ci.yml").write_text(body)
    return load_repository(tmp_path)


class TestFixtures:
    def test_naive_declares_nothing(self) -> None:
        assert _rules(_fixture("naive")) == ["I4/no-egress-policy"]

    def test_partial_declares_nothing(self) -> None:
        assert _rules(_fixture("partial")) == ["I4/no-egress-policy"]

    def test_hardened_is_clean(self) -> None:
        assert _rules(_fixture("hardened")) == []
        assert i4.evaluate(_fixture("hardened")).status is Status.PASSING

    def test_monorepo_reports_only_the_publishing_job(self) -> None:
        report = i4.evaluate(_fixture("monorepo"))
        assert [f.location.path for f in report.findings] == [
            ".github/workflows/release.yml"
        ]


class TestPolicyMode:
    def test_audit_mode_is_reported_as_telemetry(self, tmp_path: Path) -> None:
        """A control that reports after the fact is not a control."""
        repository = _repo(
            tmp_path,
            "name: ci\non: push\npermissions: {}\njobs:\n  a:\n    steps:\n"
            f"      - uses: {HARDEN} # v2\n"
            "        with:\n          egress-policy: audit\n"
            "      - run: make build\n",
        )
        assert _rules(repository) == ["I4/egress-audit-only"]

    def test_a_harden_step_with_no_mode_defaults_to_audit(self, tmp_path: Path) -> None:
        """The upstream default is audit. Assuming block would invent a control."""
        repository = _repo(
            tmp_path,
            "name: ci\non: push\npermissions: {}\njobs:\n  a:\n    steps:\n"
            f"      - uses: {HARDEN} # v2\n      - run: make build\n",
        )
        assert _rules(repository) == ["I4/egress-audit-only"]

    def test_block_mode_is_accepted(self, tmp_path: Path) -> None:
        repository = _repo(
            tmp_path,
            "name: ci\non: push\npermissions: {}\njobs:\n  a:\n    steps:\n"
            f"      - uses: {HARDEN} # v2\n"
            "        with:\n          egress-policy: block\n"
            "      - run: make build\n",
        )
        assert _rules(repository) == []


class TestOrdering:
    def test_a_policy_installed_after_another_step_is_high_severity(
        self, tmp_path: Path
    ) -> None:
        """Everything before it ran unrestricted. That window is the finding."""
        repository = _repo(
            tmp_path,
            "name: ci\non: push\npermissions: {}\njobs:\n  a:\n    steps:\n"
            "      - run: curl https://example.invalid/setup.sh | sh\n"
            f"      - uses: {HARDEN} # v2\n"
            "        with:\n          egress-policy: block\n",
        )
        report = i4.evaluate(repository)
        assert [f.rule_id for f in report.findings] == ["I4/egress-policy-applied-late"]
        assert report.findings[0].severity is Severity.HIGH


class TestScope:
    def test_a_job_with_no_steps_has_nothing_to_confine(self, tmp_path: Path) -> None:
        repository = _repo(
            tmp_path,
            "name: ci\non: push\npermissions: {}\njobs:\n"
            "  a:\n    uses: ./.github/workflows/other.yml\n",
        )
        assert _rules(repository) == []

    def test_a_local_egress_guard_is_accepted(self, tmp_path: Path) -> None:
        repository = _repo(
            tmp_path,
            "name: ci\non: push\npermissions: {}\njobs:\n  a:\n    steps:\n"
            "      - uses: ./.github/actions/egress-guard\n      - run: make build\n",
        )
        assert _rules(repository) == []


def test_the_enforcement_caveat_reaches_the_report() -> None:
    """The narrowest claim of the four invariants, stated where a reader sees it."""
    report = i4.evaluate(_fixture("hardened"))
    assert report.note == i4.ENFORCEMENT_CAVEAT
    assert "cannot confirm the runner platform enforced it" in (report.note or "")


def test_an_unparsable_workflow_leaves_the_invariant_unverified() -> None:
    assert i4.evaluate(_fixture("invalid-yaml")).status is Status.UNVERIFIED
