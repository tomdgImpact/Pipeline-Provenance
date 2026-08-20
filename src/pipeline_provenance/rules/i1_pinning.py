"""I1 — nothing runs unpinned.

A tag is a mutable pointer. Every executable reference must resolve to an
immutable identifier, so that the code reviewed at merge time is the code
executed at run time.

What this module cannot check: whether the pinned digest is the *right* one.
Pinning is an integrity control, not an identity control — a typosquatted
package pinned on day one is faithfully preserved. See threat model T-03/T-04.
"""

from __future__ import annotations

from pipeline_provenance.discovery import Repository
from pipeline_provenance.model import (
    Finding,
    Invariant,
    InvariantReport,
    Location,
    Severity,
)
from pipeline_provenance.rules.base import (
    IMAGE_DIGEST,
    has_version_comment,
    is_pinned_action,
    split_action,
    unparsable_findings,
)

INVARIANT = Invariant.I1_PINNING


def _unpinned_actions(repository: Repository) -> list[Finding]:
    findings: list[Finding] = []
    for workflow, job in repository.jobs():
        for step in job.steps:
            if not step.uses or not step.is_third_party:
                continue
            if is_pinned_action(step.uses):
                continue
            name, ref = split_action(step.uses)
            findings.append(
                Finding(
                    rule_id="I1/unpinned-action",
                    invariant=INVARIANT,
                    severity=Severity.HIGH,
                    title="Action referenced by a mutable pointer",
                    detail=(
                        f"Job '{job.name}' runs {name} at '{ref or 'no ref'}'. A "
                        "tag or branch can be repointed by the publisher at any "
                        "time, so the code reviewed at merge time is not "
                        "necessarily the code executed at run time."
                    ),
                    location=Location(workflow.path, step.line),
                    remediation=(
                        "Pin to the full 40-character commit SHA and keep the "
                        "version in a trailing comment."
                    ),
                    evidence=workflow.source(step.line),
                    threat_ids=("T-02",),
                )
            )
    return findings


def _missing_version_comments(repository: Repository) -> list[Finding]:
    findings: list[Finding] = []
    for workflow, job in repository.jobs():
        for step in job.steps:
            if not step.uses or not step.is_third_party:
                continue
            if not is_pinned_action(step.uses):
                continue
            if has_version_comment(workflow.source(step.line)):
                continue
            findings.append(
                Finding(
                    rule_id="I1/missing-version-comment",
                    invariant=INVARIANT,
                    severity=Severity.LOW,
                    title="Pinned reference has no readable version",
                    detail=(
                        f"Job '{job.name}' pins a digest with no version comment. "
                        "The pin is sound; the review is not, because no human "
                        "reading the diff can tell which release it names."
                    ),
                    location=Location(workflow.path, step.line),
                    remediation=(
                        "Append the version as a comment: "
                        "`uses: owner/repo@<sha> # v1.2.3`."
                    ),
                    evidence=workflow.source(step.line),
                    threat_ids=("T-02",),
                )
            )
    return findings


def _unpinned_images(repository: Repository) -> list[Finding]:
    findings: list[Finding] = []
    for workflow, job in repository.jobs():
        candidates: list[tuple[str, int | None, str]] = []
        if job.container_image:
            candidates.append((job.container_image, job.container_line, "container"))
        candidates.extend(
            (image, line, "service") for image, line in job.service_images
        )
        for image, line, kind in candidates:
            if IMAGE_DIGEST.search(image):
                continue
            findings.append(
                Finding(
                    rule_id="I1/unpinned-image",
                    invariant=INVARIANT,
                    severity=Severity.HIGH,
                    title="Container image referenced without a digest",
                    detail=(
                        f"Job '{job.name}' runs in the {kind} image '{image}'. A "
                        "tag on a base image can be replaced between the build "
                        "that was reviewed and the build that ships."
                    ),
                    location=Location(workflow.path, line),
                    remediation="Reference the image by `@sha256:` digest.",
                    evidence=workflow.source(line),
                    threat_ids=("T-06",),
                )
            )
    return findings


def _unhashed_dependencies(repository: Repository) -> list[Finding]:
    if any(manifest.kind == "lockfile" for manifest in repository.manifests):
        return []
    return [
        Finding(
            rule_id="I1/unhashed-dependencies",
            invariant=INVARIANT,
            severity=Severity.MEDIUM,
            title="Dependency manifest resolves without hashes",
            detail=(
                f"{manifest.path} pins no hashes and no lockfile was found. The "
                "build resolves whatever the index serves at the time it runs."
            ),
            location=Location(manifest.path),
            remediation=(
                "Commit a lockfile, or generate hashes and install with "
                "`--require-hashes`."
            ),
            threat_ids=("T-03", "T-04"),
        )
        for manifest in repository.manifests
        if manifest.kind == "requirements" and not manifest.hashed
    ]


def evaluate(repository: Repository) -> InvariantReport:
    findings = (
        _unpinned_actions(repository)
        + _unpinned_images(repository)
        + _unhashed_dependencies(repository)
        + _missing_version_comments(repository)
    )
    return InvariantReport(
        invariant=INVARIANT,
        findings=tuple(findings) + unparsable_findings(repository, INVARIANT),
        note=(
            "Pinning is an integrity control, not an identity control: a "
            "reference pinned to the wrong thing stays wrong."
        ),
    )
