"""The measurement harness is code, and a wrong benchmark is worse than none."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from benchmarks import detection, performance

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


class TestDeclaredIntent:
    def test_the_denominator_comes_from_the_hand_written_table(self) -> None:
        """Not from expected.json, which the tool generated."""
        declared = detection.declared_defects(FIXTURES / "naive")
        assert sum(declared.values()) == 13
        assert declared["I1/unpinned-action"] == 3

    def test_a_fixture_without_intent_is_an_error_not_a_zero(
        self, tmp_path: Path
    ) -> None:
        """Silently scoring an undeclared fixture as perfect is how a benchmark
        inflates itself."""
        with pytest.raises(FileNotFoundError):
            detection.declared_defects(tmp_path)


class TestRatio:
    def test_an_empty_denominator_is_none_not_one(self) -> None:
        """A precision of 1.0 computed over nothing is the most misleading
        number a benchmark can print."""
        assert detection._ratio(0, 0) is None
        assert detection._ratio(3, 4) == 0.75


class TestMeasurement:
    def test_false_positives_and_negatives_are_counted_separately(self) -> None:
        measurement = detection.Measurement(
            fixture="x",
            declared=Counter({"I1/a": 2, "I2/b": 1}),
            reported=Counter({"I1/a": 1, "I3/c": 1}),
        )
        assert measurement.true_positives == 1
        assert measurement.false_negatives == 2
        assert measurement.false_positives == 1


class TestReport:
    def test_every_figure_ships_with_its_caveats(self) -> None:
        report = detection.run()
        assert report["caveats"]
        assert any("synthetic" in caveat for caveat in report["caveats"])
        assert report["ruleset_version"]

    def test_the_corpus_is_described_not_just_counted(self) -> None:
        report = detection.run()
        assert report["corpus"]["kind"]
        assert report["corpus"]["repositories"] == 6

    def test_recall_is_perfect_on_the_declared_corpus(self) -> None:
        """If this drops, a rule stopped finding something it was written for."""
        report = detection.run()
        assert report["sc_001_detection"]["recall"] == 1.0

    def test_no_false_positive_on_the_clean_fixtures(self) -> None:
        report = detection.run()
        clean = report["sc_002_false_positives_on_clean_repositories"]
        assert clean["false_positives"] == 0


class TestPerformance:
    def test_a_timing_records_the_machine_it_ran_on(self) -> None:
        """A timing without its hardware is one nobody can reproduce."""
        report = performance.run()
        assert report["machine"]["platform"]
        assert report["machine"]["python"]

    def test_auditing_this_repository_stays_well_inside_the_budget(self) -> None:
        """SC-008 allows 5 s. This asserts an order of magnitude, not a
        micro-benchmark, so it does not fail on a loaded CI runner."""
        row = performance.time_audit(Path(__file__).resolve().parents[2], repeats=3)
        assert row["median_ms"] < 5000
