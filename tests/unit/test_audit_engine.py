"""The engine assembles a result; these tests assert it does not overstate one."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_provenance.audit import audit
from pipeline_provenance.model import AuditResult, ExitCode, Invariant, Status

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"
STAMP = "2026-08-20T00:00:00Z"


def _audit(name: str) -> AuditResult:
    return audit(FIXTURES / name, generated_at=STAMP)


class TestCompleteness:
    @pytest.mark.parametrize(
        "fixture", ["naive", "partial", "hardened", "invalid-yaml", "no-workflows"]
    )
    def test_all_four_invariants_are_always_reported(self, fixture: str) -> None:
        """Omitting a passing invariant lets a reader assume it was checked."""
        result = _audit(fixture)
        assert [r.invariant for r in result.invariants] == list(Invariant)

    def test_examined_files_include_the_ones_that_did_not_parse(self) -> None:
        """A file that broke the parser was still examined."""
        result = _audit("invalid-yaml")
        assert result.workflows_examined == (".github/workflows/broken.yml",)


class TestExitCodes:
    @pytest.mark.parametrize(
        ("fixture", "expected"),
        [
            ("hardened", ExitCode.CLEAN),
            ("naive", ExitCode.FINDINGS),
            ("partial", ExitCode.FINDINGS),
            ("monorepo", ExitCode.FINDINGS),
            ("invalid-yaml", ExitCode.FINDINGS),
            ("no-workflows", ExitCode.NOTHING_TO_AUDIT),
        ],
    )
    def test_the_contract_holds_across_every_fixture(
        self, fixture: str, expected: ExitCode
    ) -> None:
        assert _audit(fixture).exit_code is expected

    def test_an_unreadable_repository_is_not_reported_as_clean(self) -> None:
        assert _audit("invalid-yaml").exit_code is not ExitCode.CLEAN


class TestNaiveFixture:
    def test_the_planted_defect_count_matches_the_declared_intent(self) -> None:
        """intent.md lists thirteen defects. Equality, not containment: a new
        false positive fails here."""
        assert len(_audit("naive").findings) == 13

    def test_every_finding_maps_to_a_row_of_the_attack_table(self) -> None:
        for finding in _audit("naive").findings:
            assert finding.threat_ids, f"{finding.rule_id} maps to no threat row"


class TestHardenedFixture:
    def test_the_false_positive_control_is_clean(self) -> None:
        result = _audit("hardened")
        assert result.findings == ()
        assert all(r.status is Status.PASSING for r in result.invariants)


class TestHonesty:
    def test_the_egress_enforcement_caveat_is_always_present(self) -> None:
        """The tool reads declarations; it cannot confirm the platform enforced
        them. That gap is stated on every run, including a clean one."""
        for fixture in ("hardened", "naive"):
            statements = " ".join(_audit(fixture).unverifiable)
            assert "cannot confirm the runner platform enforced it" in statements

    def test_a_parse_failure_is_named_in_the_unverifiable_list(self) -> None:
        statements = _audit("invalid-yaml").unverifiable
        assert any("does not parse" in statement for statement in statements)

    def test_unverifiable_statements_are_deduplicated(self) -> None:
        statements = _audit("naive").unverifiable
        assert len(statements) == len(set(statements))


class TestDeterminism:
    def test_two_runs_over_the_same_input_produce_the_same_document(self) -> None:
        assert _audit("naive").to_dict() == _audit("naive").to_dict()

    def test_the_timestamp_is_injected_not_read_from_the_clock(self) -> None:
        assert _audit("naive").generated_at == STAMP


class TestReferences:
    def test_every_third_party_action_appears_with_its_pin_state(self) -> None:
        references = _audit("naive").references
        actions = [r for r in references if r.kind.value == "action"]
        assert len(actions) == 3
        assert all(r.pinned is False for r in actions)

    def test_a_pinned_action_records_its_resolved_digest(self) -> None:
        references = _audit("hardened").references
        actions = [r for r in references if r.kind.value == "action"]
        assert actions
        assert all(r.pinned and r.resolved and len(r.resolved) == 40 for r in actions)

    def test_dependency_manifests_are_listed(self) -> None:
        references = _audit("naive").references
        manifests = [r for r in references if r.kind.value == "dependency-manifest"]
        assert [r.raw for r in manifests] == ["requirements.txt"]
