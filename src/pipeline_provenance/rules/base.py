"""Helpers shared by the four invariant modules.

The only interesting thing here is :func:`unparsable_findings`. Every invariant
has to answer the same question about a file it could not read, and the answer
is always the same: not "passing", not "failing", but "unverified", once per
invariant, so the report says plainly that four checks did not run.
"""

from __future__ import annotations

import re

from pipeline_provenance.discovery import Repository, Step, Workflow
from pipeline_provenance.model import (
    Assessment,
    Finding,
    Invariant,
    Location,
    Severity,
)

#: A pinned action reference names a 40-character commit SHA.
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
#: A pinned image reference names a digest.
IMAGE_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def split_action(uses: str) -> tuple[str, str | None]:
    """Split ``owner/repo/path@ref`` into its name and its ref."""
    if uses.startswith("docker://"):
        return uses, None
    name, separator, ref = uses.partition("@")
    return (name, ref) if separator else (name, None)


def is_pinned_action(uses: str) -> bool:
    _, ref = split_action(uses)
    return ref is not None and bool(COMMIT_SHA.match(ref))


def has_version_comment(source_line: str | None) -> bool:
    """Whether a pinned reference carries a human-readable version beside it.

    The comment is ours and cannot be repointed by the publisher, so it costs
    nothing in integrity and buys back the readability that pinning removes.
    """
    return source_line is not None and "#" in source_line.split("@", 1)[-1]


def step_location(workflow: Workflow, step: Step) -> Location:
    return Location(workflow.path, step.line)


def unparsable_findings(
    repository: Repository, invariant: Invariant
) -> tuple[Finding, ...]:
    """One unverified finding per unreadable workflow, per invariant.

    Four findings for one broken file reads as verbose until you notice that
    four separate checks genuinely did not run. Collapsing them to one would
    let three invariants report passing on a file nobody could read.
    """
    return tuple(
        Finding(
            rule_id=f"{invariant.value}/unparsable-workflow",
            invariant=invariant,
            severity=Severity.MEDIUM,
            title="Workflow could not be parsed",
            detail=(
                f"{workflow.path} does not parse as YAML, so {invariant.value} "
                f"could not be assessed for it: {workflow.parse_error}"
            ),
            location=Location(workflow.path, workflow.parse_error_line),
            remediation=(
                "Fix the YAML. Until the file parses, no automated check can "
                "make any statement about it."
            ),
            assessment=Assessment.UNVERIFIED,
            evidence=workflow.source(workflow.parse_error_line),
        )
        for workflow in repository.unparsable_workflows
    )
