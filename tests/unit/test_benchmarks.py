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


class TestDistributionStudy:
    """The online study is opt-in, aggregate-only, and says so."""

    def test_it_refuses_without_the_online_flag(self) -> None:
        """A figure derived from nothing is worse than a missing figure."""
        import subprocess
        import sys

        process = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "benchmarks.distribution"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parents[2],
            check=False,
        )
        assert process.returncode == 2
        assert "opt-in" in process.stderr

    def test_the_corpus_is_committed_so_the_sample_is_reproducible(self) -> None:
        from benchmarks import distribution

        repositories = [
            line.strip()
            for line in distribution.CORPUS.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert len(repositories) >= 10
        assert all("/" in name for name in repositories)

    def test_no_published_figure_names_an_individual_repository(self) -> None:
        """SC-003 forbids it. The point is the shape of the distribution, and
        naming projects would turn a measurement into an accusation."""
        import json

        published = Path(__file__).resolve().parents[2] / "benchmarks" / "published"
        from benchmarks import distribution

        names = [
            line.strip()
            for line in distribution.CORPUS.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        for report in published.glob("distribution-*.json"):
            text = json.dumps(json.loads(report.read_text()))
            for name in names:
                assert name not in text, f"{report.name} names {name}"

    def test_every_published_figure_records_its_ruleset(self) -> None:
        import json

        published = Path(__file__).resolve().parents[2] / "benchmarks" / "published"
        reports = list(published.glob("*.json"))
        assert reports, "no published figures found"
        for report in reports:
            document = json.loads(report.read_text())
            assert document["ruleset_version"]
            assert document["caveats"]
