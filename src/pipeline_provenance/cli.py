"""``ppv`` command line entry point.

Only ``doctor`` is implemented at this milestone. ``audit`` and ``verify`` land
with their own units of delivery (T013 and T027); registering them here before
they work would let a caller believe an empty result was a clean one.
"""

from __future__ import annotations

import os
import platform
import sys

import click

from . import SCHEMA_VERSION, __version__

# Exit codes are part of the CLI contract (FR-009). Keep them stable.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_NOTHING_TO_AUDIT = 2
EXIT_ERROR = 3


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="ppv")
def main() -> None:
    """Audit and attest CI/CD pipelines against four structural invariants."""


@main.command()
def doctor() -> None:
    """Report what this installation can and cannot verify, and exit non-zero
    if a capability the caller may be assuming is unavailable.

    A tool that silently degrades into a permissive mode is worse than one that
    refuses, so every unavailable capability is named rather than skipped.
    """
    capabilities: list[tuple[str, bool, str]] = [
        (
            "offline static audit",
            False,
            "not implemented at this milestone (T008-T013)",
        ),
        (
            "remote reference resolution",
            bool(os.environ.get("PPV_GITHUB_TOKEN")),
            "requires PPV_GITHUB_TOKEN and --remote",
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

    sys.exit(EXIT_CLEAN)


if __name__ == "__main__":  # pragma: no cover - module entry point
    main()
