"""I3 — every artifact carries verifiable provenance, and deployment verifies it.

Two halves, and the second is the one that matters. Generating an attestation
nobody checks is decorative: it costs build time, it appears in the release, and
it stops exactly nothing. So this module reports the absence of *verification*
separately from the absence of *generation*.

The verification finding is reported as ``unverified``, not as a failure. The
admission point may legitimately live outside this repository — in an admission
controller, a registry policy, a deployment system this tool cannot see. Absence
of evidence here is not evidence of absence, and claiming otherwise would be a
false positive on a correctly configured setup.
"""

from __future__ import annotations

from pipeline_provenance.discovery import Repository, Workflow
from pipeline_provenance.model import (
    Assessment,
    Finding,
    Invariant,
    InvariantReport,
    Location,
    Severity,
)
from pipeline_provenance.rules.base import unparsable_findings

INVARIANT = Invariant.I3_PROVENANCE

PROVENANCE_ACTIONS = (
    "actions/attest-build-provenance",
    "actions/attest",
    "slsa-framework/slsa-github-generator",
)
PROVENANCE_COMMANDS = ("cosign attest", "slsa-generator", "ppv attest")

SBOM_ACTIONS = ("anchore/sbom-action", "cyclonedx", "aquasecurity/trivy-action")
SBOM_COMMANDS = ("syft ", "cdxgen", "cyclonedx-py", "trivy sbom")

VERIFY_COMMANDS = (
    "gh attestation verify",
    "cosign verify",
    "slsa-verifier verify",
    "ppv verify",
)
VERIFY_ACTIONS = ("sigstore/cosign-installer",)


def _mentions(
    workflow: Workflow, actions: tuple[str, ...], commands: tuple[str, ...]
) -> bool:
    for job in workflow.jobs:
        for step in job.steps:
            if step.uses and any(marker in step.uses for marker in actions):
                return True
            if step.run and any(marker in step.run for marker in commands):
                return True
    return False


def _emits_provenance(workflow: Workflow) -> bool:
    return _mentions(workflow, PROVENANCE_ACTIONS, PROVENANCE_COMMANDS)


def _emits_sbom(workflow: Workflow) -> bool:
    return _mentions(workflow, SBOM_ACTIONS, SBOM_COMMANDS)


def _verifies(repository: Repository) -> bool:
    return any(
        _mentions(workflow, VERIFY_ACTIONS, VERIFY_COMMANDS)
        for workflow in repository.parsed_workflows
    )


def _producing_jobs(repository: Repository) -> list[tuple[Workflow, str, int]]:
    return [
        (workflow, job.name, job.line)
        for workflow, job in repository.jobs()
        if job.produces_artifact
    ]


def evaluate(repository: Repository) -> InvariantReport:
    findings: list[Finding] = []
    producers = _producing_jobs(repository)

    for workflow, job_name, line in producers:
        if not _emits_provenance(workflow):
            findings.append(
                Finding(
                    rule_id="I3/no-provenance",
                    invariant=INVARIANT,
                    severity=Severity.HIGH,
                    title="Artifact produced without provenance",
                    detail=(
                        f"Job '{job_name}' produces something deployable and "
                        f"{workflow.path} emits no build provenance. Nothing "
                        "downstream can establish which source, which runner and "
                        "which identity produced it."
                    ),
                    location=Location(workflow.path, line),
                    remediation=(
                        "Emit an in-toto SLSA provenance statement for the "
                        "artifact and sign it under the workflow identity."
                    ),
                    evidence=workflow.source(line),
                    threat_ids=("T-12",),
                )
            )
        if not _emits_sbom(workflow):
            findings.append(
                Finding(
                    rule_id="I3/no-sbom",
                    invariant=INVARIANT,
                    severity=Severity.MEDIUM,
                    title="Artifact produced without a bill of materials",
                    detail=(
                        f"Job '{job_name}' produces something deployable and "
                        f"{workflow.path} emits no SBOM. Provenance answers where "
                        "the artifact came from; only an SBOM answers what is "
                        "inside it, which is the question a component policy asks."
                    ),
                    location=Location(workflow.path, line),
                    remediation=(
                        "Generate a CycloneDX SBOM and sign it with the provenance."
                    ),
                    evidence=workflow.source(line),
                    threat_ids=("T-12",),
                )
            )

    if producers and not _verifies(repository):
        findings.append(
            Finding(
                rule_id="I3/no-admission-verification",
                invariant=INVARIANT,
                severity=Severity.MEDIUM,
                title="No admission-time verification found in this repository",
                detail=(
                    "This repository produces deployable artifacts and nothing in "
                    "it verifies an attestation. The admission point may live "
                    "elsewhere — an admission controller, a registry policy — "
                    "which this tool cannot see, so this is reported as "
                    "unverified rather than as a failure."
                ),
                location=Location(producers[0][0].path, None),
                remediation=(
                    "Verify signature, provenance predicate and expected signer "
                    "identity at the point production accepts the artifact, and "
                    "record where that happens."
                ),
                assessment=Assessment.UNVERIFIED,
                threat_ids=("T-12",),
            )
        )

    note = (
        "Provenance proves where an artifact came from, never that it is correct."
        if producers
        else "No job in this repository produces a deployable artifact."
    )
    return InvariantReport(
        invariant=INVARIANT,
        findings=tuple(findings) + unparsable_findings(repository, INVARIANT),
        note=note,
    )
