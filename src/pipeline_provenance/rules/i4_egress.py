"""I4 — egress from build jobs is denied by default.

A build that suddenly talks to a new host should fail rather than succeed
quietly. Without that, exfiltration is indistinguishable from a package
download, which is what makes it the cheapest possible move for an attacker who
already has execution inside the job (threat model T-08, T-09).

This module has the narrowest honest claim of the four. It can see whether a
job *declares* an egress policy; it cannot see whether the runner platform
*enforces* one. That gap is recorded on the invariant note and in the result's
`unverifiable` list rather than being quietly folded into a pass.
"""

from __future__ import annotations

from typing import Any

from pipeline_provenance.discovery import Job, Repository
from pipeline_provenance.model import (
    Finding,
    Invariant,
    InvariantReport,
    Location,
    Severity,
)
from pipeline_provenance.rules.base import unparsable_findings

INVARIANT = Invariant.I4_EGRESS

#: Actions that install a network policy for the remainder of the job.
EGRESS_ACTIONS = ("step-security/harden-runner",)
#: Local composite actions this project ships for the same purpose.
LOCAL_EGRESS_ACTIONS = ("./.github/actions/egress-guard",)

#: The statement added to the result whenever this invariant is assessed, so a
#: reader is never left believing the tool proved more than it did.
ENFORCEMENT_CAVEAT = (
    "I4 is assessed by declaration only: this tool reads what a workflow asks "
    "for, and cannot confirm the runner platform enforced it."
)


def _egress_step(job: Job) -> tuple[Any, str] | None:
    """Return the egress-policy step and its declared mode, if any."""
    for step in job.steps:
        if not step.uses:
            continue
        if any(step.uses.startswith(marker) for marker in LOCAL_EGRESS_ACTIONS):
            return step, str(step.with_.get("mode", "block"))
        if any(marker in step.uses for marker in EGRESS_ACTIONS):
            return step, str(step.with_.get("egress-policy", "audit"))
    return None


def evaluate(repository: Repository) -> InvariantReport:
    findings: list[Finding] = []

    for workflow, job in repository.jobs():
        if not job.steps:
            # Nothing executes, so there is nothing to confine.
            continue

        declared = _egress_step(job)
        if declared is None:
            findings.append(
                Finding(
                    rule_id="I4/no-egress-policy",
                    invariant=INVARIANT,
                    severity=Severity.MEDIUM,
                    title="Job declares no egress policy",
                    detail=(
                        f"Job '{job.name}' runs with unrestricted outbound "
                        "network access. Any step, including a third-party "
                        "action, can reach any host, and exfiltration looks "
                        "exactly like a package download."
                    ),
                    location=Location(workflow.path, job.line),
                    remediation=(
                        "Declare a default-deny egress policy with an explicit "
                        "allowlist, applied before any third-party step runs."
                    ),
                    evidence=workflow.source(job.line),
                    threat_ids=("T-08", "T-09"),
                )
            )
            continue

        step, mode = declared
        if mode != "block":
            findings.append(
                Finding(
                    rule_id="I4/egress-audit-only",
                    invariant=INVARIANT,
                    severity=Severity.MEDIUM,
                    title="Egress policy observes but does not block",
                    detail=(
                        f"Job '{job.name}' declares egress policy '{mode}'. "
                        "Traffic to an unlisted host is recorded and allowed. A "
                        "control that reports after the fact is telemetry, not a "
                        "control."
                    ),
                    location=Location(workflow.path, step.line),
                    remediation="Set the egress policy to block.",
                    evidence=workflow.source(step.line),
                    threat_ids=("T-08",),
                )
            )
            continue

        if step.index != 0:
            findings.append(
                Finding(
                    rule_id="I4/egress-policy-applied-late",
                    invariant=INVARIANT,
                    severity=Severity.HIGH,
                    title="Egress policy applied after another step has run",
                    detail=(
                        f"Job '{job.name}' installs its egress policy at step "
                        f"{step.index + 1}. Everything before it ran with "
                        "unrestricted network access, which is the window an "
                        "attacker needs."
                    ),
                    location=Location(workflow.path, step.line),
                    remediation="Make the egress policy the first step of the job.",
                    evidence=workflow.source(step.line),
                    threat_ids=("T-08",),
                )
            )

    return InvariantReport(
        invariant=INVARIANT,
        findings=tuple(findings) + unparsable_findings(repository, INVARIANT),
        note=ENFORCEMENT_CAVEAT,
    )
