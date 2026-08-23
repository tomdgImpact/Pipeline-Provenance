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


class TestInvariantScope:
    """`--invariant` narrows what blocks, never what is reported."""

    def test_scoping_to_a_clean_invariant_passes(self) -> None:
        code, output = _gate(
            str(FIXTURES / "partial"), "--invariant", "I1", "--fail-on", "critical"
        )
        assert code == 0
        assert "gate: passed for I1." in output

    def test_scoping_to_a_failing_invariant_still_fails(self) -> None:
        code, output = _gate(str(FIXTURES / "partial"), "--invariant", "I3")
        assert code == 1
        assert "in I3" in output

    def test_findings_outside_the_scope_are_still_reported(self) -> None:
        """Narrowing the gate must not narrow the finding list. A team that
        gates on I1 alone still needs to see what I2 through I4 found."""
        _, output = _gate(
            str(FIXTURES / "partial"), "--invariant", "I1", "--fail-on", "critical"
        )
        assert "I3/no-provenance" in output
        assert "I4/no-egress-policy" in output

    def test_a_narrowed_pass_says_what_it_did_not_enforce(self) -> None:
        """The whole risk of a partial gate: a green tick that reads as
        compliance. The verdict line names the gap."""
        _, output = _gate(
            str(FIXTURES / "partial"), "--invariant", "I1", "--fail-on", "critical"
        )
        assert "NOT enforced: I2, I3, I4" in output
        assert "5 finding(s) reported and not blocked" in output

    def test_a_narrowed_failure_also_says_what_it_did_not_enforce(self) -> None:
        """Printed on both paths. A reader who sees only the verdict must not be
        able to mistake a partial gate for a full one either way."""
        _, output = _gate(str(FIXTURES / "partial"), "--invariant", "I3")
        assert "NOT enforced:" in output

    def test_several_invariants_can_be_enforced_together(self) -> None:
        code, output = _gate(
            str(FIXTURES / "partial"),
            "--invariant",
            "I1",
            "--invariant",
            "I2",
            "--fail-on",
            "critical",
        )
        assert code == 0
        assert "NOT enforced: I3, I4" in output

    def test_the_default_enforces_all_four_and_says_nothing_extra(self) -> None:
        """An unnarrowed gate must not print a scope caveat it does not need."""
        _, output = _gate(str(FIXTURES / "hardened"))
        assert "NOT enforced" not in output
        assert "gate: passed." in output

    def test_an_unknown_invariant_is_rejected(self) -> None:
        code, output = _gate(str(FIXTURES / "partial"), "--invariant", "I9")
        assert code != 0
        assert "I9" in output

    def test_unverified_checks_outside_the_scope_do_not_block(self) -> None:
        """`partial` carries an unverified I3 finding. Gating on I1 alone must
        not fail on it, or the narrowing would be meaningless."""
        code, _ = _gate(
            str(FIXTURES / "partial"), "--invariant", "I1", "--fail-on", "critical"
        )
        assert code == 0

    def test_unverified_checks_inside_the_scope_still_block(self) -> None:
        code, output = _gate(
            str(FIXTURES / "partial"), "--invariant", "I3", "--fail-on", "critical"
        )
        assert code == 1
        assert "could not be completed" in output
