"""I2 — secrets are scoped to the job that needs them."""

from __future__ import annotations

from pathlib import Path

from pipeline_provenance.discovery import Repository, load_repository
from pipeline_provenance.model import Severity, Status
from pipeline_provenance.rules import i2_least_privilege as i2

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def _rules(repository: Repository) -> list[str]:
    return sorted(f.rule_id for f in i2.evaluate(repository).findings)


def _fixture(name: str) -> Repository:
    return load_repository(FIXTURES / name)


def _repo(tmp_path: Path, body: str, name: str = "ci.yml") -> Repository:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(body)
    return load_repository(tmp_path)


class TestNaiveFixture:
    def test_every_planted_defect_is_reported(self) -> None:
        assert _rules(_fixture("naive")) == [
            "I2/implicit-token-scope",
            "I2/no-default-deny",
            "I2/persisted-credentials",
            "I2/privileged-trigger",
        ]

    def test_a_privileged_trigger_checking_out_fork_code_is_critical(self) -> None:
        """T-10. The trigger alone is high; fork code executing under it is not."""
        report = i2.evaluate(_fixture("naive"))
        trigger = next(
            f for f in report.findings if f.rule_id == "I2/privileged-trigger"
        )
        assert trigger.severity is Severity.CRITICAL
        assert "fork-controlled code" in trigger.detail


class TestHardenedFixture:
    def test_no_finding_is_reported(self) -> None:
        assert _rules(_fixture("hardened")) == []

    def test_attestation_scopes_are_not_flagged_as_excessive(self) -> None:
        """`id-token` and `attestations` mint a short-lived identity and cannot
        modify the repository. Flagging them trains a reader to ignore the rule."""
        assert "I2/excessive-permission" not in _rules(_fixture("hardened"))


class TestPartialFixture:
    def test_only_the_repository_write_scope_is_reported(self) -> None:
        report = i2.evaluate(_fixture("partial"))
        assert [f.rule_id for f in report.findings] == ["I2/excessive-permission"]
        assert "contents" in report.findings[0].detail
        assert "id-token" not in report.findings[0].detail


class TestDefaultDeny:
    def test_a_declared_empty_block_denies_and_is_not_reported(
        self, tmp_path: Path
    ) -> None:
        """`permissions: {}` and a missing block are not the same thing."""
        repository = _repo(
            tmp_path,
            "name: ci\non: push\npermissions: {}\njobs:\n  a:\n"
            "    steps:\n      - run: make test\n",
        )
        assert _rules(repository) == []

    def test_a_missing_block_is_reported_at_both_levels(self, tmp_path: Path) -> None:
        repository = _repo(
            tmp_path,
            "name: ci\non: push\njobs:\n  a:\n    steps:\n      - run: make test\n",
        )
        assert _rules(repository) == ["I2/implicit-token-scope", "I2/no-default-deny"]

    def test_a_job_scope_overrides_a_missing_top_level_block(
        self, tmp_path: Path
    ) -> None:
        repository = _repo(
            tmp_path,
            "name: ci\non: push\njobs:\n  a:\n    permissions:\n      contents: read\n"
            "    steps:\n      - run: make test\n",
        )
        assert _rules(repository) == ["I2/no-default-deny"]


class TestPersistedCredentials:
    def test_explicit_false_clears_the_finding(self, tmp_path: Path) -> None:
        sha = "a" * 40
        repository = _repo(
            tmp_path,
            "name: ci\non: push\npermissions: {}\njobs:\n  a:\n    steps:\n"
            f"      - uses: actions/checkout@{sha} # v5\n"
            "        with:\n          persist-credentials: false\n",
        )
        assert _rules(repository) == []

    def test_a_truthy_value_does_not_clear_it(self, tmp_path: Path) -> None:
        """Only an explicit false counts; anything else leaves the token behind."""
        sha = "a" * 40
        repository = _repo(
            tmp_path,
            "name: ci\non: push\npermissions: {}\njobs:\n  a:\n    steps:\n"
            f"      - uses: actions/checkout@{sha} # v5\n"
            "        with:\n          persist-credentials: true\n",
        )
        assert _rules(repository) == ["I2/persisted-credentials"]


class TestPrivilegedTriggers:
    def test_a_plain_pull_request_trigger_is_not_privileged(
        self, tmp_path: Path
    ) -> None:
        repository = _repo(
            tmp_path,
            "name: ci\non:\n  pull_request:\npermissions: {}\njobs:\n  a:\n"
            "    steps:\n      - run: make test\n",
        )
        assert _rules(repository) == []

    def test_workflow_run_is_treated_as_privileged(self, tmp_path: Path) -> None:
        repository = _repo(
            tmp_path,
            "name: ci\non:\n  workflow_run:\n    workflows: [ci]\n"
            "permissions: {}\njobs:\n  a:\n    steps:\n      - run: make test\n",
        )
        assert _rules(repository) == ["I2/privileged-trigger"]

    def test_the_trigger_alone_is_high_not_critical(self, tmp_path: Path) -> None:
        repository = _repo(
            tmp_path,
            "name: ci\non:\n  pull_request_target:\npermissions: {}\njobs:\n  a:\n"
            "    steps:\n      - run: make test\n",
        )
        finding = next(
            f
            for f in i2.evaluate(repository).findings
            if f.rule_id == "I2/privileged-trigger"
        )
        assert finding.severity is Severity.HIGH


class TestMonorepoFixture:
    def test_findings_are_confined_to_the_workflow_that_publishes(self) -> None:
        report = i2.evaluate(_fixture("monorepo"))
        assert {f.location.path for f in report.findings} == {
            ".github/workflows/release.yml"
        }
        assert sorted(f.rule_id for f in report.findings) == [
            "I2/excessive-permission",
            "I2/persisted-credentials",
        ]

    def test_two_clean_workflows_do_not_dilute_one_failing_one(self) -> None:
        assert i2.evaluate(_fixture("monorepo")).status is Status.FAILING


def test_an_unparsable_workflow_leaves_the_invariant_unverified() -> None:
    report = i2.evaluate(_fixture("invalid-yaml"))
    assert report.status is Status.UNVERIFIED
