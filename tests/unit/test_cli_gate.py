"""The policy gate: what it blocks, and what it refuses to call a pass."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pipeline_provenance.cli import main

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def _gate(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(main, ["gate", *args])
    return result.exit_code, result.output


class TestBlocking:
    def test_a_hardened_repository_passes(self) -> None:
        code, output = _gate(str(FIXTURES / "hardened"))
        assert code == 0
        assert "gate: passed." in output

    def test_a_naive_repository_fails(self) -> None:
        code, output = _gate(str(FIXTURES / "naive"))
        assert code == 1
        assert "gate: FAILED" in output

    def test_every_violation_is_reported_in_one_run(self) -> None:
        """A team migrating an existing repository needs the whole list. A gate
        that stops at the first finding turns adoption into a fail-fix loop
        they abandon on the fourth iteration."""
        _, output = _gate(str(FIXTURES / "naive"))
        assert output.count("fix:") == 13


class TestThreshold:
    def test_raising_the_threshold_lets_lower_severities_through(self) -> None:
        """The migration path: start at critical, tighten as the list shrinks."""
        code, output = _gate(
            str(FIXTURES / "partial"), "--fail-on", "critical", "--allow-unverified"
        )
        assert code == 0
        assert "gate: passed." in output

    def test_a_threshold_still_blocks_at_its_own_level(self) -> None:
        """`partial` carries a high finding, so --fail-on high must not pass it."""
        code, _ = _gate(
            str(FIXTURES / "partial"), "--fail-on", "high", "--allow-unverified"
        )
        assert code == 1

    def test_the_default_threshold_blocks_everything(self) -> None:
        code, _ = _gate(str(FIXTURES / "partial"))
        assert code == 1

    def test_a_critical_threshold_still_blocks_a_critical(self) -> None:
        code, _ = _gate(
            str(FIXTURES / "naive"), "--fail-on", "critical", "--allow-unverified"
        )
        assert code == 1


class TestUnverified:
    def test_an_unverified_check_blocks_by_default(self) -> None:
        """A gate that passes on "I could not tell" is not a gate."""
        code, output = _gate(str(FIXTURES / "partial"), "--fail-on", "critical")
        assert code == 1
        assert "could not be completed" in output

    def test_accepting_unverified_checks_is_explicit(self) -> None:
        code, _ = _gate(
            str(FIXTURES / "partial"), "--fail-on", "critical", "--allow-unverified"
        )
        assert code == 0


class TestNothingToAudit:
    def test_an_empty_repository_is_not_a_pass(self) -> None:
        code, output = _gate(str(FIXTURES / "no-workflows"))
        assert code == 2
        assert "This is not a pass" in output
