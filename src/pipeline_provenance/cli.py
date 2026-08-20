"""``ppv`` command line entry point.

The CLI's contract is its exit codes, not its prose. ``verify`` is deliberately
still absent: a registered command that returns an empty result reads to a
caller as a clean result, and this project exists to argue against exactly that.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

import click

from pipeline_provenance import SCHEMA_VERSION, __version__
from pipeline_provenance.audit import audit as run_audit
from pipeline_provenance.model import (
    Assessment,
    AuditResult,
    ExitCode,
    Status,
)

STATUS_MARK: dict[Status, str] = {
    Status.PASSING: "pass",
    Status.FAILING: "FAIL",
    Status.UNVERIFIED: "????",
}


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="ppv")
def main() -> None:
    """Audit and attest CI/CD pipelines against four structural invariants."""


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option(
    "--remote/--no-remote",
    default=False,
    help="Resolve references over the network. Requires PPV_GITHUB_TOKEN.",
)
def audit(path: Path, remote: bool) -> None:
    """Audit PATH against the four structural invariants.

    Offline by default. Exit codes: 0 assessed and clean, 1 findings or
    something that could not be assessed, 2 nothing to audit, 3 error.
    """
    if remote:
        if not os.environ.get("PPV_GITHUB_TOKEN"):
            raise click.ClickException(
                "--remote needs PPV_GITHUB_TOKEN. Refusing rather than silently "
                "falling back to an offline run and reporting it as complete."
            )
        raise click.ClickException(
            "remote reference resolution is not implemented at this milestone; "
            "run without --remote for a complete offline audit."
        )

    result = run_audit(path)
    _render_text(result)
    sys.exit(result.exit_code)


def _render_text(result: AuditResult) -> None:
    """Human-readable summary. The machine-readable formats are the contract."""
    click.echo(f"ppv {result.tool_version}  ruleset {result.ruleset_version}")
    click.echo(f"target: {result.target}")

    if not result.workflows_examined:
        click.echo("")
        click.echo("Nothing to audit: no workflow definitions found.")
        click.echo(
            "This repository has not been found compliant. It has not been assessed."
        )
        return

    click.echo(f"workflows examined: {len(result.workflows_examined)}")
    click.echo("")
    for report in result.invariants:
        mark = STATUS_MARK[report.status]
        click.echo(f"  [{mark}] {report.invariant.value}  {report.invariant.label}")

    findings = result.findings
    if findings:
        click.echo("")
        click.echo(f"{len(findings)} finding(s):")
        for finding in findings:
            flag = "" if finding.assessment is Assessment.VERIFIED else " (unverified)"
            click.echo("")
            click.echo(f"  {finding.severity.value.upper():8} {finding.rule_id}{flag}")
            click.echo(f"           {finding.location}")
            click.echo(f"           {finding.title}")
            if finding.evidence:
                click.echo(f"           > {finding.evidence}")
            click.echo(f"           fix: {finding.remediation}")

    if result.unverifiable:
        click.echo("")
        click.echo("Could not be established by this run:")
        for statement in result.unverifiable:
            click.echo(f"  - {statement}")

    click.echo("")
    summary = result.to_dict()["summary"]
    click.echo(
        f"{summary['verified']} confirmed, {summary['unverified']} unverified, "
        f"{summary['by_severity']['critical']} critical, "
        f"{summary['by_severity']['high']} high."
    )


@main.command()
def doctor() -> None:
    """Report what this installation can and cannot verify.

    A tool that silently degrades into a permissive mode is worse than one that
    refuses, so every unavailable capability is named rather than skipped.
    """
    capabilities: list[tuple[str, bool, str]] = [
        ("offline static audit", True, "`ppv audit <path>`"),
        (
            "remote reference resolution",
            False,
            "not implemented at this milestone (T013 follow-up)",
        ),
        (
            "admission verification",
            False,
            "not implemented at this milestone (T027)",
        ),
        (
            "expected signer identity configured",
            bool(os.environ.get("PPV_EXPECTED_SIGNER_IDENTITY")),
            "PPV_EXPECTED_SIGNER_IDENTITY has no default, by design",
        ),
    ]

    click.echo(f"ppv {__version__}  (result schema {SCHEMA_VERSION})")
    click.echo(f"python {platform.python_version()} on {platform.system().lower()}")
    click.echo("")

    for name, available, note in capabilities:
        marker = "available" if available else "UNAVAILABLE"
        click.echo(f"  [{marker:>11}] {name} - {note}")

    click.echo("")
    click.echo("Capabilities reported UNAVAILABLE are not silently degraded: any")
    click.echo("command depending on one refuses to run rather than returning a")
    click.echo("result that looks clean.")

    sys.exit(ExitCode.CLEAN)


if __name__ == "__main__":  # pragma: no cover - module entry point
    main()
