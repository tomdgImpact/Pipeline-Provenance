"""Assemble one :class:`AuditResult` from the four invariant modules.

The engine's only real responsibility is refusing to overstate what it did. It
records what it examined, what it could not assess, and it never drops an
invariant from the report — a report that omits a passing invariant lets a
reader assume it was checked when it may simply have been skipped.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

from pipeline_provenance.discovery import Repository, load_repository
from pipeline_provenance.model import (
    AuditResult,
    Invariant,
    InvariantReport,
    Location,
    Reference,
    ReferenceKind,
    Status,
)
from pipeline_provenance.rules import (
    i1_pinning,
    i2_least_privilege,
    i3_provenance,
    i4_egress,
)
from pipeline_provenance.rules.base import IMAGE_DIGEST, is_pinned_action

Evaluator = Callable[[Repository], InvariantReport]

#: Order is the reporting order. It matches the README and the threat model, so
#: a reader moving between the three does not have to re-orient.
EVALUATORS: tuple[Evaluator, ...] = (
    i1_pinning.evaluate,
    i2_least_privilege.evaluate,
    i3_provenance.evaluate,
    i4_egress.evaluate,
)


def _references(repository: Repository) -> tuple[Reference, ...]:
    found: list[Reference] = []
    for workflow, job in repository.jobs():
        for step in job.steps:
            if step.uses and step.is_third_party:
                found.append(
                    Reference(
                        raw=step.uses,
                        kind=ReferenceKind.ACTION,
                        location=Location(workflow.path, step.line),
                        resolved=step.uses.partition("@")[2] or None
                        if is_pinned_action(step.uses)
                        else None,
                        pinned=is_pinned_action(step.uses),
                    )
                )
        images = list(job.service_images)
        if job.container_image:
            images.append((job.container_image, job.container_line or job.line))
        found.extend(
            Reference(
                raw=image,
                kind=ReferenceKind.IMAGE,
                location=Location(workflow.path, line),
                resolved=image.partition("@")[2] or None,
                pinned=bool(IMAGE_DIGEST.search(image)),
            )
            for image, line in images
        )
    found.extend(
        Reference(
            raw=manifest.path,
            kind=ReferenceKind.DEPENDENCY_MANIFEST,
            location=Location(manifest.path),
            resolved=None,
            pinned=manifest.hashed,
        )
        for manifest in repository.manifests
    )
    return tuple(found)


def _unverifiable(
    repository: Repository, reports: Iterable[InvariantReport]
) -> tuple[str, ...]:
    """Everything this run could not establish, in one place.

    A reader who only skims the summary must still be able to see the size of
    the gap, so these statements are collected at the top level rather than
    left scattered across per-finding notes.
    """
    statements: list[str] = []
    for workflow in repository.unparsable_workflows:
        statements.append(
            f"{workflow.path} does not parse; no invariant could be assessed for it"
        )
    for report in reports:
        if report.status is Status.UNVERIFIED and report.note:
            statements.append(f"{report.invariant.value}: {report.note}")
    statements.append(i4_egress.ENFORCEMENT_CAVEAT)
    return tuple(dict.fromkeys(statements))


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def audit(root: Path, *, generated_at: str | None = None) -> AuditResult:
    """Audit ``root`` offline and return the canonical result.

    ``generated_at`` is injectable so that two runs over the same input produce
    the same document, which is what lets the end-to-end suite assert whole
    documents instead of fragments.
    """
    repository = load_repository(root)
    reports = tuple(evaluate(repository) for evaluate in EVALUATORS)

    missing = [i for i in Invariant if i not in {r.invariant for r in reports}]
    if missing:  # pragma: no cover - guards a programming error, not input
        raise RuntimeError(f"evaluator missing for {missing}")

    return AuditResult(
        target=root.resolve().as_posix(),
        generated_at=generated_at or _now(),
        invariants=reports,
        references=_references(repository),
        unverifiable=_unverifiable(repository, reports),
        workflows_examined=tuple(w.path for w in repository.workflows),
    )
