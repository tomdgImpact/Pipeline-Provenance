"""The CLI contract: what a caller sees, and what it exits with."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pipeline_provenance.cli import main

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def _run(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(main, list(args))
    return result.exit_code, result.output


class TestExitCodes:
    def test_a_hardened_repository_exits_clean(self) -> None:
        code, _ = _run("audit", str(FIXTURES / "hardened"))
        assert code == 0

    def test_findings_exit_one(self) -> None:
        code, _ = _run("audit", str(FIXTURES / "naive"))
        assert code == 1

    def test_nothing_to_audit_has_its_own_code(self) -> None:
        code, output = _run("audit", str(FIXTURES / "no-workflows"))
        assert code == 2
        assert "has not been found compliant" in output

    def test_a_missing_path_is_an_error_not_a_clean_run(self) -> None:
        code, _ = _run("audit", str(FIXTURES / "does-not-exist"))
        assert code != 0


class TestOutput:
    def test_findings_are_ordered_most_severe_first(self) -> None:
        _, output = _run("audit", str(FIXTURES / "naive"))
        severities = [
            line.split()[0]
            for line in output.splitlines()
            if line.startswith("  ") and "I" in line and "/" in line
        ]
        ranking = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        ranks = [ranking[s] for s in severities if s in ranking]
        assert ranks == sorted(ranks)

    def test_every_finding_carries_a_location_and_a_fix(self) -> None:
        _, output = _run("audit", str(FIXTURES / "naive"))
        assert output.count("fix:") == 13
        assert ".github/workflows/build.yml:" in output

    def test_unverified_findings_are_labelled_as_such(self) -> None:
        _, output = _run("audit", str(FIXTURES / "naive"))
        assert "(unverified)" in output

    def test_what_could_not_be_established_is_printed(self) -> None:
        _, output = _run("audit", str(FIXTURES / "hardened"))
        assert "Could not be established by this run:" in output


class TestRemote:
    def test_remote_without_a_token_refuses(self) -> None:
        """Falling back to an offline run and reporting it as complete is the
        failure mode; refusing is the whole design."""
        code, output = _run("audit", str(FIXTURES / "naive"), "--remote")
        assert code != 0
        assert "PPV_GITHUB_TOKEN" in output

    def test_remote_with_a_token_refuses_because_it_is_not_implemented(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["audit", str(FIXTURES / "naive"), "--remote"],
            env={"PPV_GITHUB_TOKEN": "not-a-real-token"},
        )
        assert result.exit_code != 0
        assert "not implemented" in result.output


def test_an_unknown_command_is_an_error() -> None:
    """No command silently accepts an argument it does not understand."""
    code, output = _run("attest")
    assert code != 0
    assert "No such command" in output
