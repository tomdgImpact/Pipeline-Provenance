"""The result contract.

These tests exist because every other surface derives from this module: if the
scoring rules here are wrong, three renderers are confidently wrong together.
"""

from __future__ import annotations

import pytest

from pipeline_provenance.model import (
    Assessment,
    AuditResult,
    ExitCode,
    Finding,
    Invariant,
    InvariantReport,
    Location,
    Severity,
    Status,
)


def _finding(
    assessment: Assessment = Assessment.VERIFIED,
    severity: Severity = Severity.HIGH,
    invariant: Invariant = Invariant.I1_PINNING,
    *,
    rule_id: str = "I1/unpinned-action",
    path: str = ".github/workflows/ci.yml",
    line: int = 12,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        invariant=invariant,
        severity=severity,
        title="Action referenced by tag",
        detail="A tag is a mutable pointer.",
        location=Location(path, line),
        remediation="Pin to a commit SHA.",
        assessment=assessment,
        threat_ids=("T-02",),
    )


def _result(
    *reports: InvariantReport,
    workflows: tuple[str, ...] = (".github/workflows/ci.yml",),
) -> AuditResult:
    present = {report.invariant for report in reports}
    filled = list(reports) + [
        InvariantReport(invariant=i) for i in Invariant if i not in present
    ]
    return AuditResult(
        target="fixture",
        generated_at="2026-08-20T00:00:00Z",
        invariants=tuple(filled),
        workflows_examined=workflows,
    )


class TestInvariantStatus:
    def test_no_findings_is_passing(self) -> None:
        assert InvariantReport(Invariant.I1_PINNING).status is Status.PASSING

    def test_a_verified_finding_fails_the_invariant(self) -> None:
        report = InvariantReport(Invariant.I1_PINNING, findings=(_finding(),))
        assert report.status is Status.FAILING

    def test_only_unverified_findings_is_unverified_not_passing(self) -> None:
        """FR-005. Reporting this as passing would be a false negative on
        exactly the repositories that most need the finding."""
        report = InvariantReport(
            Invariant.I3_PROVENANCE,
            findings=(_finding(assessment=Assessment.UNVERIFIED),),
        )
        assert report.status is Status.UNVERIFIED

    def test_an_unassessable_invariant_is_unverified_even_with_no_findings(
        self,
    ) -> None:
        report = InvariantReport(
            Invariant.I4_EGRESS,
            assessable=False,
            note="runner platform cannot enforce egress control",
        )
        assert report.status is Status.UNVERIFIED

    def test_counts_separate_verified_from_unverified(self) -> None:
        report = InvariantReport(
            Invariant.I1_PINNING,
            findings=(
                _finding(),
                _finding(assessment=Assessment.UNVERIFIED, rule_id="I1/unresolved"),
            ),
        )
        counts = report.to_dict()["counts"]
        assert counts == {"total": 2, "verified": 1, "unverified": 1}


class TestExitCode:
    def test_nothing_examined_is_not_clean(self) -> None:
        """A repository with no workflows has not been found compliant."""
        result = _result(workflows=())
        assert result.exit_code is ExitCode.NOTHING_TO_AUDIT

    def test_all_invariants_passing_is_clean(self) -> None:
        assert _result().exit_code is ExitCode.CLEAN

    def test_a_verified_finding_is_non_zero(self) -> None:
        result = _result(InvariantReport(Invariant.I1_PINNING, findings=(_finding(),)))
        assert result.exit_code is ExitCode.FINDINGS

    def test_an_unverified_invariant_is_non_zero(self) -> None:
        """Exit 0 is a positive claim. "I could not tell" is not a yes."""
        result = _result(
            InvariantReport(
                Invariant.I3_PROVENANCE,
                assessable=False,
                note="no admission point discoverable",
            )
        )
        assert result.exit_code is ExitCode.FINDINGS

    def test_the_four_codes_are_distinct_and_stable(self) -> None:
        """Callers gate on these numbers; they are an API."""
        assert (ExitCode.CLEAN, ExitCode.FINDINGS) == (0, 1)
        assert (ExitCode.NOTHING_TO_AUDIT, ExitCode.ERROR) == (2, 3)


class TestOrdering:
    def test_findings_sort_by_severity_then_location(self) -> None:
        low = _finding(severity=Severity.LOW, line=99, rule_id="I1/low")
        critical = _finding(severity=Severity.CRITICAL, line=1, rule_id="I1/critical")
        medium = _finding(severity=Severity.MEDIUM, line=50, rule_id="I1/medium")
        result = _result(
            InvariantReport(Invariant.I1_PINNING, findings=(low, critical, medium))
        )
        assert [f.rule_id for f in result.findings] == [
            "I1/critical",
            "I1/medium",
            "I1/low",
        ]

    def test_ordering_is_deterministic_across_equal_severities(self) -> None:
        first = _finding(path="a.yml", line=2, rule_id="I1/a")
        second = _finding(path="a.yml", line=1, rule_id="I1/b")
        result = _result(
            InvariantReport(Invariant.I1_PINNING, findings=(first, second))
        )
        assert [f.location.line for f in result.findings] == [1, 2]


class TestSerialisation:
    def test_document_is_self_describing(self) -> None:
        document = _result().to_dict()
        assert document["schema_version"]
        assert document["ruleset_version"]
        assert document["generated_at"] == "2026-08-20T00:00:00Z"

    def test_generated_at_is_supplied_not_read_from_the_clock(self) -> None:
        """Two runs over the same input must produce the same document."""
        assert _result().to_dict() == _result().to_dict()

    def test_summary_counts_only_verified_findings_by_severity(self) -> None:
        result = _result(
            InvariantReport(
                Invariant.I1_PINNING,
                findings=(
                    _finding(severity=Severity.CRITICAL),
                    _finding(
                        severity=Severity.CRITICAL,
                        assessment=Assessment.UNVERIFIED,
                        rule_id="I1/unresolved",
                    ),
                ),
            )
        )
        summary = result.to_dict()["summary"]
        assert summary["total"] == 2
        assert summary["verified"] == 1
        assert summary["unverified"] == 1
        assert summary["by_severity"]["critical"] == 1

    def test_every_invariant_appears_even_when_it_has_nothing_to_say(self) -> None:
        """A report that omits a passing invariant lets a reader assume it was
        checked when it may simply have been dropped."""
        document = _result().to_dict()
        assert [i["invariant"] for i in document["invariants"]] == [
            "I1",
            "I2",
            "I3",
            "I4",
        ]

    def test_every_invariant_has_a_human_label(self) -> None:
        for invariant in Invariant:
            assert invariant.label
            assert invariant.label != str(invariant)


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.CRITICAL, 0),
        (Severity.HIGH, 1),
        (Severity.MEDIUM, 2),
        (Severity.LOW, 3),
    ],
)
def test_severity_rank_is_total(severity: Severity, expected: int) -> None:
    assert severity.rank == expected


def test_location_renders_without_a_line() -> None:
    assert str(Location("README.md")) == "README.md"
    assert str(Location("README.md", 4)) == "README.md:4"
