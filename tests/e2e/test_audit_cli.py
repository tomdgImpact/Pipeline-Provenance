"""The shipped entry point, driven the way a user drives it.

Nothing here imports the package's internals. Every assertion goes through a
real process invocation, so anything that only works because a test held the
objects in memory fails here.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"
REPO_ROOT = Path(__file__).resolve().parents[2]
CASES = ["naive", "partial", "hardened", "invalid-yaml", "no-workflows", "monorepo"]


def run_ppv(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Invoke the CLI as a separate process, exactly as a user would."""
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "pipeline_provenance.cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd or REPO_ROOT,
        check=False,
    )


def expected(fixture: str) -> dict[str, Any]:
    return dict(json.loads((FIXTURES / fixture / "expected.json").read_text()))


def actual(fixture: str) -> tuple[int, dict[str, Any]]:
    process = run_ppv("audit", str(FIXTURES / fixture), "--format", "json")
    return process.returncode, dict(json.loads(process.stdout))


class TestFixtureCorpus:
    @pytest.mark.parametrize("fixture", CASES)
    def test_the_finding_set_matches_exactly(self, fixture: str) -> None:
        """Equality, not containment. A new false positive fails here as loudly
        as a missed detection, which is the whole point of a fixture corpus."""
        code, document = actual(fixture)
        reference = expected(fixture)

        reported = [
            {
                "rule_id": finding["rule_id"],
                "path": finding["location"]["path"],
                "line": finding["location"]["line"],
                "severity": finding["severity"],
                "assessment": finding["assessment"],
                "threat_ids": finding["threat_ids"],
            }
            for finding in document["findings"]
        ]
        assert reported == reference["findings"]
        assert code == reference["exit_code"]

    @pytest.mark.parametrize("fixture", CASES)
    def test_the_invariant_statuses_match_exactly(self, fixture: str) -> None:
        _, document = actual(fixture)
        statuses = {
            report["invariant"]: report["status"] for report in document["invariants"]
        }
        assert statuses == expected(fixture)["invariants"]

    @pytest.mark.parametrize("fixture", CASES)
    def test_what_could_not_be_established_matches_exactly(self, fixture: str) -> None:
        """A caveat quietly disappearing is a regression, not a cleanup."""
        _, document = actual(fixture)
        assert document["unverifiable"] == expected(fixture)["unverifiable"]


class TestExitCodeContract:
    def test_clean(self) -> None:
        assert run_ppv("audit", str(FIXTURES / "hardened")).returncode == 0

    def test_findings(self) -> None:
        assert run_ppv("audit", str(FIXTURES / "naive")).returncode == 1

    def test_nothing_to_audit(self) -> None:
        assert run_ppv("audit", str(FIXTURES / "no-workflows")).returncode == 2

    def test_a_path_that_does_not_exist_is_an_error(self) -> None:
        process = run_ppv("audit", str(FIXTURES / "absent"))
        assert process.returncode != 0
        assert process.stdout.strip() == ""

    def test_a_file_instead_of_a_directory_is_an_error(self) -> None:
        process = run_ppv("audit", str(FIXTURES / "README.md"))
        assert process.returncode != 0


class TestOutputFiles:
    @pytest.mark.parametrize("output_format", ["json", "sarif", "html", "text"])
    def test_output_can_be_written_to_a_file(
        self, output_format: str, tmp_path: Path
    ) -> None:
        destination = tmp_path / f"report.{output_format}"
        process = run_ppv(
            "audit",
            str(FIXTURES / "naive"),
            "--format",
            output_format,
            "-o",
            str(destination),
        )
        assert process.returncode == 1
        assert destination.is_file()
        assert destination.read_text().strip()

    def test_the_written_file_is_identical_to_stdout(self, tmp_path: Path) -> None:
        destination = tmp_path / "report.json"
        run_ppv(
            "audit", str(FIXTURES / "naive"), "--format", "json", "-o", str(destination)
        )
        piped = run_ppv("audit", str(FIXTURES / "naive"), "--format", "json").stdout
        written = destination.read_text()
        assert json.loads(written)["findings"] == json.loads(piped)["findings"]

    def test_the_progress_note_goes_to_stderr_not_stdout(self, tmp_path: Path) -> None:
        """So `ppv ... -o x.json > log` keeps stdout clean for piping."""
        process = run_ppv(
            "audit",
            str(FIXTURES / "naive"),
            "--format",
            "json",
            "-o",
            str(tmp_path / "r.json"),
        )
        assert process.stdout == ""
        assert "wrote json" in process.stderr


class TestRemoteRefusal:
    def test_remote_without_a_token_refuses_and_emits_no_report(self) -> None:
        process = run_ppv("audit", str(FIXTURES / "naive"), "--remote")
        assert process.returncode != 0
        assert process.stdout.strip() == ""
        assert "PPV_GITHUB_TOKEN" in process.stderr


class TestDoctor:
    def test_doctor_exits_zero_and_names_what_is_missing(self) -> None:
        process = run_ppv("doctor")
        assert process.returncode == 0
        assert "UNAVAILABLE" in process.stdout
        assert "admission verification" in process.stdout


class TestDefaultTarget:
    def test_audit_defaults_to_the_current_directory(self, tmp_path: Path) -> None:
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
            "name: ci\non: push\njobs: {}\n"
        )
        process = run_ppv("audit", "--format", "json", cwd=tmp_path)
        document = json.loads(process.stdout)
        assert document["workflows_examined"] == [".github/workflows/ci.yml"]
