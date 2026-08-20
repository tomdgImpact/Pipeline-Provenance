"""``ppv`` command line entry point.

The CLI's contract is its exit codes and its machine-readable formats, not its
prose. ``verify`` is deliberately still absent: a registered command that
returns an empty result reads to a caller as a clean result, and this project
exists to argue against exactly that.
"""

from __future__ import annotations

import os
import platform
import sys
from collections.abc import Callable
from pathlib import Path

import click

from pipeline_provenance import SCHEMA_VERSION, __version__
from pipeline_provenance.attest import verify as verify_module
from pipeline_provenance.audit import audit as run_audit
from pipeline_provenance.model import (
    Assessment,
    AuditResult,
    ExitCode,
    Severity,
    Status,
)
from pipeline_provenance.report import html_out, json_out, sarif_out

STATUS_MARK: dict[Status, str] = {
    Status.PASSING: "pass",
    Status.FAILING: "FAIL",
    Status.UNVERIFIED: "????",
}


def render_text(result: AuditResult) -> str:
    """Human-readable summary. The machine-readable formats are the contract."""
    out: list[str] = []

    def line(text: str = "") -> None:
        out.append(text + "\n")

    line(f"ppv {result.tool_version}  ruleset {result.ruleset_version}")
    line(f"target: {result.target}")

    if not result.workflows_examined:
        line()
        line("Nothing to audit: no workflow definitions found.")
        line("This repository has not been found compliant. It has not been assessed.")
        return "".join(out)

    line(f"workflows examined: {len(result.workflows_examined)}")
    line()
    for report in result.invariants:
        mark = STATUS_MARK[report.status]
        line(f"  [{mark}] {report.invariant.value}  {report.invariant.label}")

    findings = result.findings
    if findings:
        line()
        line(f"{len(findings)} finding(s):")
        for finding in findings:
            flag = "" if finding.assessment is Assessment.VERIFIED else " (unverified)"
            line()
            line(f"  {finding.severity.value.upper():8} {finding.rule_id}{flag}")
            line(f"           {finding.location}")
            line(f"           {finding.title}")
            if finding.evidence:
                line(f"           > {finding.evidence}")
            line(f"           fix: {finding.remediation}")

    if result.unverifiable:
        line()
        line("Could not be established by this run:")
        for statement in result.unverifiable:
            line(f"  - {statement}")

    line()
    summary = result.to_dict()["summary"]
    line(
        f"{summary['verified']} confirmed, {summary['unverified']} unverified, "
        f"{summary['by_severity']['critical']} critical, "
        f"{summary['by_severity']['high']} high."
    )
    return "".join(out)


#: Renderers keyed by ``--format``. Each is a projection of the same result
#: object; none computes anything of its own, so they cannot disagree.
RENDERERS: dict[str, Callable[[AuditResult], str]] = {
    "text": render_text,
    "json": json_out.render,
    "sarif": sarif_out.render,
    "html": html_out.render,
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
    "--format",
    "output_format",
    type=click.Choice(sorted(RENDERERS)),
    default="text",
    help=(
        "text for a terminal, json for the contract, sarif for code scanning, "
        "html to read."
    ),
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write to a file instead of stdout.",
)
@click.option(
    "--remote/--no-remote",
    default=False,
    help="Resolve references over the network. Requires PPV_GITHUB_TOKEN.",
)
def audit(path: Path, output_format: str, output: Path | None, remote: bool) -> None:
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
    rendered = RENDERERS[output_format](result)

    if output is None:
        click.echo(rendered, nl=False)
    else:
        output.write_text(rendered, encoding="utf-8")
        click.echo(f"wrote {output_format} to {output}", err=True)

    sys.exit(result.exit_code)


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option(
    "--fail-on",
    type=click.Choice([level.value for level in Severity]),
    default="low",
    help="Lowest severity that fails the gate. Default: everything fails it.",
)
@click.option(
    "--allow-unverified/--no-allow-unverified",
    default=False,
    help=(
        "Permit invariants this run could not assess. Off by default: a gate "
        "that passes on 'I could not tell' is not a gate."
    ),
)
def gate(path: Path, fail_on: str, allow_unverified: bool) -> None:
    """Fail the build unless PATH satisfies the four invariants.

    Reports every violation in one run rather than stopping at the first, so a
    team migrating an existing repository sees the whole list instead of
    entering a fail-fix loop they abandon on the fourth iteration.
    """
    result = run_audit(path)
    threshold = Severity(fail_on)

    if not result.workflows_examined:
        click.echo("gate: nothing to audit — no workflow definitions found.", err=True)
        click.echo(
            "This is not a pass. Point the gate at a repository with workflows.",
            err=True,
        )
        sys.exit(ExitCode.NOTHING_TO_AUDIT)

    click.echo(render_text(result), nl=False)

    blocking = [
        finding
        for finding in result.findings
        if finding.assessment is Assessment.VERIFIED
        and finding.severity.rank <= threshold.rank
    ]
    unverified = [
        finding
        for finding in result.findings
        if finding.assessment is Assessment.UNVERIFIED
    ]

    click.echo("")
    if blocking:
        click.echo(
            f"gate: FAILED — {len(blocking)} violation(s) at {fail_on} or above.",
            err=True,
        )
    if unverified and not allow_unverified:
        click.echo(
            f"gate: FAILED — {len(unverified)} check(s) could not be completed. "
            "Pass --allow-unverified to accept that, deliberately and in writing.",
            err=True,
        )

    if blocking or (unverified and not allow_unverified):
        sys.exit(ExitCode.FINDINGS)

    click.echo("gate: passed.")
    sys.exit(ExitCode.CLEAN)


@main.command()
@click.argument("subject", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--provenance",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="In-toto SLSA provenance statement.",
)
@click.option(
    "--sbom",
    "sbom_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="CycloneDX SBOM. Required: the attestation set is atomic.",
)
@click.option(
    "--expected-identity",
    default=None,
    help=(
        "Signer identity this admission point accepts. Falls back to "
        "PPV_EXPECTED_SIGNER_IDENTITY. There is no default."
    ),
)
@click.option(
    "--expected-issuer",
    default=verify_module.DEFAULT_ISSUER,
    show_default=True,
    help="OIDC issuer the signing certificate must come from.",
)
@click.option(
    "--deny-component",
    "denied",
    multiple=True,
    help="Component name that must not appear in the SBOM. Repeatable.",
)
@click.option(
    "--advisory",
    is_flag=True,
    default=False,
    help=(
        "Report without gating. For use inside a build job, where verification "
        "runs in the context it is checking and therefore proves nothing."
    ),
)
def verify(
    subject: Path,
    provenance: Path,
    sbom_path: Path,
    expected_identity: str | None,
    expected_issuer: str,
    denied: tuple[str, ...],
    advisory: bool,
) -> None:
    """Decide whether SUBJECT may be deployed.

    Refuses when the expected identity is unset, when the signature backend is
    unavailable, when the attestation does not cover this artifact, or when the
    signer is not the expected one. There is no permissive path.
    """
    identity = expected_identity or os.environ.get("PPV_EXPECTED_SIGNER_IDENTITY")

    try:
        attestation = verify_module.load_attestation(provenance, sbom_path)
    except ValueError as error:
        raise click.ClickException(str(error)) from error

    policy = verify_module.Policy(
        expected_identity=identity or "",
        expected_issuer=expected_issuer,
        denied_components=denied,
    )
    decision = verify_module.verify(subject, attestation, policy)

    if advisory:
        click.echo(
            "ADVISORY — this check ran inside the build context it is checking. "
            "It shortens the feedback loop and proves nothing (ADR-0004)."
        )

    click.echo(f"subject: {decision.subject}")
    for name, passed, detail in decision.checks:
        click.echo(f"  [{'ok  ' if passed else 'FAIL'}] {name}: {detail}")
    click.echo("")
    click.echo(f"{decision.decision.value.upper()}: {decision.reason}")

    if advisory:
        sys.exit(ExitCode.CLEAN)
    sys.exit(ExitCode.CLEAN if decision.accepted else ExitCode.FINDINGS)


@main.command()
def doctor() -> None:
    """Report what this installation can and cannot verify.

    A tool that silently degrades into a permissive mode is worse than one that
    refuses, so every unavailable capability is named rather than skipped.
    """
    capabilities: list[tuple[str, bool, str]] = [
        ("offline static audit", True, "`ppv audit <path>`"),
        ("json, sarif and html output", True, "`--format json|sarif|html`"),
        ("policy gate", True, "`ppv gate <path>`"),
        (
            "remote reference resolution",
            False,
            "not implemented at this milestone",
        ),
        (
            "admission verification",
            True,
            "`ppv verify <artifact> --provenance ... --sbom ...`",
        ),
        (
            "signature backend",
            verify_module.CosignVerifier().available()[0],
            verify_module.CosignVerifier().available()[1],
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
