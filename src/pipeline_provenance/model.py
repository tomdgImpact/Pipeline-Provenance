"""The result contract.

Every surface of this project — the CLI, the three renderers, the policy gate
and the admission verifier — is derived from the types in this module. They are
deliberately dull, frozen and free of behaviour beyond serialisation, so that
the JSON, SARIF and HTML outputs cannot drift apart: there is one object, and
three ways of printing it.

The single load-bearing design choice here is :class:`Assessment`. A check that
could not be performed produces a finding marked ``unverified``, and an
invariant with nothing but unverified findings is reported as ``unverified`` —
never as passing. Absence of evidence is not evidence of absence, and scoring it
green would be a false negative on exactly the repositories that most need the
finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Any

from . import SCHEMA_VERSION, __version__

#: Bumped whenever a rule is added, removed, or changes what it reports. A
#: published number is only comparable against the ruleset that produced it.
RULESET_VERSION = "2026.08.1"


class ExitCode(IntEnum):
    """The CLI exit-code contract (FR-009).

    ``NOTHING_TO_AUDIT`` is deliberately distinct from ``CLEAN``: a repository
    with no workflows has not been found compliant, it has not been assessed.
    Collapsing the two is how a scanner reports success on a target it never
    looked at.
    """

    CLEAN = 0
    FINDINGS = 1
    NOTHING_TO_AUDIT = 2
    ERROR = 3


class Invariant(StrEnum):
    """The four structural invariants. See ``docs/THREAT_MODEL.md``."""

    I1_PINNING = "I1"
    I2_LEAST_PRIVILEGE = "I2"
    I3_PROVENANCE = "I3"
    I4_EGRESS = "I4"

    @property
    def label(self) -> str:
        """Human-readable name. Not ``title`` — that is ``str.title``."""
        return _INVARIANT_LABELS[self]


_INVARIANT_LABELS: dict[Invariant, str] = {
    Invariant.I1_PINNING: "Nothing runs unpinned",
    Invariant.I2_LEAST_PRIVILEGE: "Secrets are scoped to the job that needs them",
    Invariant.I3_PROVENANCE: "Every artifact carries verifiable provenance",
    Invariant.I4_EGRESS: "Egress from build jobs is denied by default",
}


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

#: SARIF has no "critical"; it maps onto error with a higher rank.
SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


class Assessment(StrEnum):
    """Whether the tool actually established what it is reporting."""

    #: The check ran and the finding is a positive detection.
    VERIFIED = "verified"
    #: The check could not be performed. Reported so a reader knows the gap
    #: exists, and never counted as a pass.
    UNVERIFIED = "unverified"


class Status(StrEnum):
    PASSING = "passing"
    FAILING = "failing"
    UNVERIFIED = "unverified"


class ReferenceKind(StrEnum):
    ACTION = "action"
    IMAGE = "image"
    DEPENDENCY_MANIFEST = "dependency-manifest"


@dataclass(frozen=True, slots=True)
class Location:
    """Where a finding lives. A finding a reader cannot locate is an opinion."""

    path: str
    line: int | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line}


@dataclass(frozen=True, slots=True)
class Reference:
    """An executable reference discovered in a repository.

    ``resolved`` holds the immutable identifier the reference already names —
    a commit SHA or an image digest. It is never populated by resolving a tag
    over the network during a default run; offline is the default, and a
    resolution the caller did not ask for is a network call they did not expect.
    """

    raw: str
    kind: ReferenceKind
    location: Location
    resolved: str | None = None
    pinned: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "kind": str(self.kind),
            "location": self.location.to_dict(),
            "resolved": self.resolved,
            "pinned": self.pinned,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """One reported defect, or one gap the tool could not close.

    ``threat_ids`` binds the finding to a row of the attack table in
    ``docs/THREAT_MODEL.md``. A finding that maps to no row is either a new
    threat the model is missing, or noise.
    """

    rule_id: str
    invariant: Invariant
    severity: Severity
    title: str
    detail: str
    location: Location
    remediation: str
    assessment: Assessment = Assessment.VERIFIED
    evidence: str | None = None
    threat_ids: tuple[str, ...] = ()

    @property
    def sort_key(self) -> tuple[int, str, str, int, str]:
        return (
            self.severity.rank,
            str(self.invariant),
            self.location.path,
            self.location.line or 0,
            self.rule_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "invariant": str(self.invariant),
            "severity": str(self.severity),
            "title": self.title,
            "detail": self.detail,
            "location": self.location.to_dict(),
            "remediation": self.remediation,
            "assessment": str(self.assessment),
            "evidence": self.evidence,
            "threat_ids": list(self.threat_ids),
        }


@dataclass(frozen=True, slots=True)
class InvariantReport:
    """Per-invariant outcome.

    ``note`` carries the reason an invariant is unverified, which is the part a
    reader needs in order to decide whether to care.
    """

    invariant: Invariant
    findings: tuple[Finding, ...] = ()
    note: str | None = None
    assessable: bool = True

    @property
    def status(self) -> Status:
        if not self.assessable:
            return Status.UNVERIFIED
        if any(f.assessment is Assessment.VERIFIED for f in self.findings):
            return Status.FAILING
        if self.findings:
            return Status.UNVERIFIED
        return Status.PASSING

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant": str(self.invariant),
            "title": self.invariant.label,
            "status": str(self.status),
            "note": self.note,
            "findings": [f.rule_id for f in self.findings],
            "counts": {
                "total": len(self.findings),
                "verified": sum(
                    1 for f in self.findings if f.assessment is Assessment.VERIFIED
                ),
                "unverified": sum(
                    1 for f in self.findings if f.assessment is Assessment.UNVERIFIED
                ),
            },
        }


@dataclass(frozen=True, slots=True)
class AuditResult:
    """The single object every renderer prints.

    ``generated_at`` is supplied by the caller rather than read from the clock,
    so that a run is reproducible and a test can assert a whole document.
    """

    target: str
    generated_at: str
    invariants: tuple[InvariantReport, ...]
    references: tuple[Reference, ...] = ()
    unverifiable: tuple[str, ...] = ()
    workflows_examined: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    ruleset_version: str = RULESET_VERSION

    @property
    def findings(self) -> tuple[Finding, ...]:
        collected = [f for report in self.invariants for f in report.findings]
        return tuple(sorted(collected, key=lambda f: f.sort_key))

    @property
    def verified_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.assessment is Assessment.VERIFIED)

    @property
    def exit_code(self) -> ExitCode:
        """Exit 0 is a positive claim, not the absence of a negative one.

        ``CLEAN`` is returned only when every invariant was assessable and
        passed. An invariant the tool could not assess produces a non-zero exit,
        because a caller gating on ``$? -eq 0`` is asking "is this repository
        compliant", and "I could not tell" is not a yes.
        """
        if not self.workflows_examined:
            return ExitCode.NOTHING_TO_AUDIT
        if all(report.status is Status.PASSING for report in self.invariants):
            return ExitCode.CLEAN
        return ExitCode.FINDINGS

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "ruleset_version": self.ruleset_version,
            "target": self.target,
            "generated_at": self.generated_at,
            "workflows_examined": list(self.workflows_examined),
            "invariants": [report.to_dict() for report in self.invariants],
            "findings": [f.to_dict() for f in self.findings],
            "references": [r.to_dict() for r in self.references],
            "unverifiable": list(self.unverifiable),
            "summary": {
                "total": len(self.findings),
                "verified": len(self.verified_findings),
                "unverified": len(self.findings) - len(self.verified_findings),
                "by_severity": {
                    str(level): sum(
                        1 for f in self.verified_findings if f.severity is level
                    )
                    for level in Severity
                },
            },
        }


@dataclass(frozen=True, slots=True)
class Subject:
    """An artifact an attestation is about, named by content."""

    name: str
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "digest": {"sha256": self.sha256}}


@dataclass(frozen=True, slots=True)
class AttestationSet:
    """Provenance and SBOM, together or not at all.

    Atomicity is enforced in ``__post_init__`` rather than by a checklist in a
    workflow, because half an attestation set is not a weaker guarantee — it is
    a different and useless one. A consumer with provenance and no SBOM cannot
    answer a component question; one with an SBOM and no provenance cannot tell
    who wrote the SBOM.
    """

    subjects: tuple[Subject, ...]
    provenance: dict[str, Any]
    sbom: dict[str, Any]

    def __post_init__(self) -> None:
        if not self.subjects:
            raise ValueError("an attestation set with no subject attests to nothing")
        if not self.provenance or not self.sbom:
            raise ValueError(
                "the attestation set is atomic: provenance and SBOM are emitted "
                "together or the build fails"
            )


class Decision(StrEnum):
    ACCEPT = "accept"
    REFUSE = "refuse"


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """The outcome at the admission point, and why.

    There is no third state. Anything that is not an explicit accept is a
    refusal, including every error path — that is what "fail closed" means when
    written down as a type.
    """

    decision: Decision
    reason: str
    subject: str
    asserted_identity: str | None = None
    policy_version: str = RULESET_VERSION
    checks: tuple[tuple[str, bool, str], ...] = ()

    @property
    def accepted(self) -> bool:
        return self.decision is Decision.ACCEPT

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": str(self.decision),
            "reason": self.reason,
            "subject": self.subject,
            "asserted_identity": self.asserted_identity,
            "policy_version": self.policy_version,
            "checks": [
                {"name": name, "passed": passed, "detail": detail}
                for name, passed, detail in self.checks
            ],
        }
