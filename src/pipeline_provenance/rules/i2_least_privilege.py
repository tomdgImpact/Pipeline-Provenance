"""I2 — secrets are scoped to the job that needs them.

Every step in a job can read every secret and every token scope that job holds.
The adversary in the threat model is a third-party action running inside the
job (ADV-2), so the question this module asks is not "is this scope used?" but
"what would a compromised step in this job be able to do?".

What this module cannot check: whether a scope a job legitimately holds is
being used safely. A job that genuinely needs `contents: write` still hands that
write access to every action it runs.
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

INVARIANT = Invariant.I2_LEAST_PRIVILEGE

#: Triggers that expose repository write scope to code an outside contributor
#: controls. See threat model T-10.
PRIVILEGED_TRIGGERS = frozenset({"pull_request_target", "workflow_run"})

#: Write scopes that are minimal by construction: they exist only to mint a
#: short-lived attestation identity and cannot be used to modify the
#: repository. Flagging these would train a reader to ignore the rule.
ATTESTATION_SCOPES = frozenset({"id-token", "attestations"})

#: Expressions that resolve to code the fork author controls.
FORK_CONTROLLED = (
    "github.event.pull_request.head",
    "github.event.workflow_run.head",
)


def _write_scopes(permissions: Any) -> list[str]:
    if not isinstance(permissions, dict):
        return []
    return [
        str(scope)
        for scope, level in permissions.items()
        if str(level) == "write" and str(scope) not in ATTESTATION_SCOPES
    ]


def _no_default_deny(repository: Repository) -> list[Finding]:
    return [
        Finding(
            rule_id="I2/no-default-deny",
            invariant=INVARIANT,
            severity=Severity.MEDIUM,
            title="Workflow inherits the repository default token scope",
            detail=(
                f"{workflow.path} declares no top-level `permissions:` block, so "
                "every job that does not declare its own inherits whatever the "
                "repository default happens to be — a setting that can change "
                "outside this file."
            ),
            location=Location(workflow.path, 1),
            remediation=(
                "Add `permissions: {}` at the top level and grant each job the "
                "minimum it needs."
            ),
            threat_ids=("T-01",),
        )
        for workflow in repository.parsed_workflows
        if not workflow.permissions_declared
    ]


def _implicit_job_scope(repository: Repository) -> list[Finding]:
    findings: list[Finding] = []
    for workflow, job in repository.jobs():
        if job.permissions_declared:
            continue
        if workflow.permissions_declared and workflow.permissions in ({}, None):
            # The workflow already denies by default; the job inherits nothing.
            continue
        findings.append(
            Finding(
                rule_id="I2/implicit-token-scope",
                invariant=INVARIANT,
                severity=Severity.HIGH,
                title="Job runs with an undeclared token scope",
                detail=(
                    f"Job '{job.name}' declares no `permissions:` block. Every "
                    "third-party step it runs holds whatever scope it inherited."
                ),
                location=Location(workflow.path, job.line),
                remediation=(
                    "Declare `permissions:` on the job with only the scopes it uses."
                ),
                evidence=workflow.source(job.line),
                threat_ids=("T-01",),
            )
        )
    return findings


def _excessive_permissions(repository: Repository) -> list[Finding]:
    findings: list[Finding] = []
    for workflow, job in repository.jobs():
        scopes = _write_scopes(job.permissions)
        if not scopes:
            continue
        findings.append(
            Finding(
                rule_id="I2/excessive-permission",
                invariant=INVARIANT,
                severity=Severity.MEDIUM,
                title="Job holds repository write scope",
                detail=(
                    f"Job '{job.name}' grants write on {', '.join(sorted(scopes))}. "
                    "Every step in the job, including third-party actions, can "
                    "use it. Write scope is an exception that has to be argued "
                    "for, not a default."
                ),
                location=Location(workflow.path, job.permissions_line or job.line),
                remediation=(
                    "Move the step that needs write into its own job, or drop the "
                    "scope. Keep `id-token`/`attestations` for signing only."
                ),
                evidence=workflow.source(job.permissions_line),
                threat_ids=("T-01",),
            )
        )
    return findings


def _checks_out_fork_code(job: Job) -> bool:
    return any(
        marker in str(value)
        for step in job.steps
        for value in step.with_.values()
        for marker in FORK_CONTROLLED
    )


def _privileged_triggers(repository: Repository) -> list[Finding]:
    findings: list[Finding] = []
    for workflow in repository.parsed_workflows:
        triggers = sorted(set(workflow.triggers) & PRIVILEGED_TRIGGERS)
        if not triggers:
            continue
        fork_code = any(_checks_out_fork_code(job) for job in workflow.jobs)
        findings.append(
            Finding(
                rule_id="I2/privileged-trigger",
                invariant=INVARIANT,
                severity=Severity.CRITICAL if fork_code else Severity.HIGH,
                title="Privileged trigger reachable from an untrusted fork",
                detail=(
                    f"{workflow.path} triggers on {', '.join(triggers)}, which runs "
                    "with repository write scope and access to secrets in the "
                    "context of the base repository."
                    + (
                        " A step checks out fork-controlled code, so an outside "
                        "contributor's code executes with that scope."
                        if fork_code
                        else ""
                    )
                ),
                location=Location(workflow.path, 1),
                remediation=(
                    "Use `pull_request` instead, or split the privileged work "
                    "into a separate workflow that never checks out fork code."
                ),
                threat_ids=("T-10",),
            )
        )
    return findings


def _persisted_credentials(repository: Repository) -> list[Finding]:
    findings: list[Finding] = []
    for workflow, job in repository.jobs():
        for step in job.steps:
            if not step.uses or not step.uses.startswith("actions/checkout@"):
                continue
            if step.with_.get("persist-credentials") is False:
                continue
            findings.append(
                Finding(
                    rule_id="I2/persisted-credentials",
                    invariant=INVARIANT,
                    severity=Severity.MEDIUM,
                    title="Checkout leaves a credential in the runner's git config",
                    detail=(
                        f"Job '{job.name}' checks out without "
                        "`persist-credentials: false`, so the token stays in "
                        "`.git/config` for every later step in the job to read."
                    ),
                    location=Location(workflow.path, step.line),
                    remediation="Set `persist-credentials: false` on the checkout.",
                    evidence=workflow.source(step.line),
                    threat_ids=("T-01",),
                )
            )
    return findings


def evaluate(repository: Repository) -> InvariantReport:
    findings = (
        _privileged_triggers(repository)
        + _implicit_job_scope(repository)
        + _excessive_permissions(repository)
        + _persisted_credentials(repository)
        + _no_default_deny(repository)
    )
    return InvariantReport(
        invariant=INVARIANT,
        findings=tuple(findings) + unparsable_findings(repository, INVARIANT),
        note=(
            "Scope held is scope every step in the job can use. This module "
            "cannot tell whether a scope a job legitimately needs is used safely."
        ),
    )
