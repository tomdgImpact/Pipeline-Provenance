"""The CLI contract that other units of delivery are allowed to depend on."""

from __future__ import annotations

from click.testing import CliRunner

from pipeline_provenance import SCHEMA_VERSION, __version__
from pipeline_provenance.cli import main


def test_version_is_reported() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_doctor_reports_the_schema_version() -> None:
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert f"result schema {SCHEMA_VERSION}" in result.output


def test_doctor_names_every_unavailable_capability() -> None:
    """An unavailable capability must be printed, not omitted.

    Omission is how a self-report turns into a false clean bill of health.
    """
    result = CliRunner().invoke(main, ["doctor"])
    assert "UNAVAILABLE" in result.output
    assert "offline static audit" in result.output
    assert "admission verification" in result.output


def test_only_working_commands_are_registered() -> None:
    """A registered command that returns an empty result reads as a clean one.

    Every command in this list does something. `audit`, `gate` and `verify`
    each graduated out of the unregistered set when they started working;
    nothing was ever registered ahead of its implementation.
    """
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    registered = {"audit", "gate", "verify", "doctor"}
    assert registered <= set(result.output.split())
