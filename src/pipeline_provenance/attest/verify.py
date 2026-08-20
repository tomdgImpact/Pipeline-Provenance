"""Admission-time verification.

This is the only place in the project where a decision is made. Everything
upstream produces documents; this decides whether production accepts them.

Three properties are deliberate and each is tested:

* **No permissive default.** With no expected signer identity configured the
  verifier refuses to run at all. An identity that defaults to "any" turns
  verification into decoration, which is worse than no verification because it
  reads as a control.
* **Cannot verify means refuse.** If the signature backend is unavailable, or
  the transparency log is unreachable, the answer is refuse — never "accept,
  could not check".
* **Every check is recorded.** The decision carries the list of checks that ran
  and their outcomes, so an operator can reconstruct why an artifact was let in
  without re-running anything.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from pipeline_provenance.attest.provenance import digest
from pipeline_provenance.model import (
    AdmissionDecision,
    AttestationSet,
    Decision,
)

DEFAULT_ISSUER = "https://token.actions.githubusercontent.com"
Check = tuple[str, bool, str]


class SignatureVerifier(Protocol):
    """A backend that can establish who signed an artifact.

    ``name`` is a read-only property rather than an attribute so that a frozen
    implementation satisfies the protocol; a verifier with mutable identity is
    not something this project wants to make expressible.
    """

    @property
    def name(self) -> str: ...

    def available(self) -> tuple[bool, str]:
        """Whether this backend can run here, and why not if it cannot."""

    def verify(self, subject: Path, identity: str, issuer: str) -> tuple[bool, str]:
        """Whether ``subject`` carries a valid signature from ``identity``."""


@dataclass(frozen=True, slots=True)
class CosignVerifier:
    """Keyless verification through the cosign CLI.

    Absence of the binary is reported as unavailable rather than skipped. A
    verifier that quietly does nothing when its backend is missing is the exact
    failure this project exists to argue against.
    """

    name: str = "cosign"
    binary: str = "cosign"
    timeout_seconds: int = 60

    def available(self) -> tuple[bool, str]:
        if shutil.which(self.binary) is None:
            return False, f"{self.binary} is not installed on this host"
        return True, f"{self.binary} found"

    def verify(self, subject: Path, identity: str, issuer: str) -> tuple[bool, str]:
        command = [
            self.binary,
            "verify-blob-attestation",
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            issuer,
            str(subject),
        ]
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return False, f"{self.binary} could not be run: {error}"
        if completed.returncode != 0:
            return False, (completed.stderr or completed.stdout).strip()[:400]
        return True, f"{self.binary} accepted the signature for {identity}"


@dataclass(frozen=True, slots=True)
class Policy:
    """What this admission point requires.

    ``expected_identity`` has no default anywhere in the codebase. It is the
    caller's job to supply it, and the verifier refuses without it.
    """

    expected_identity: str
    expected_issuer: str = DEFAULT_ISSUER
    denied_components: tuple[str, ...] = ()
    require_sbom_components: bool = False
    checks_required: tuple[str, ...] = field(default=(), repr=False)


def _builder_id(attestation: AttestationSet) -> str | None:
    predicate = attestation.provenance.get("predicate")
    if not isinstance(predicate, dict):
        return None
    run_details = predicate.get("runDetails")
    if not isinstance(run_details, dict):
        return None
    builder = run_details.get("builder")
    if not isinstance(builder, dict):
        return None
    identity = builder.get("id")
    return str(identity) if identity else None


def _sbom_component_names(attestation: AttestationSet) -> list[str]:
    components = attestation.sbom.get("components")
    if not isinstance(components, list):
        return []
    return [str(item.get("name", "")) for item in components if isinstance(item, dict)]


def _refuse(subject: str, reason: str, checks: list[Check]) -> AdmissionDecision:
    return AdmissionDecision(
        decision=Decision.REFUSE,
        reason=reason,
        subject=subject,
        checks=tuple(checks),
    )


def verify(
    subject: Path,
    attestation: AttestationSet,
    policy: Policy,
    verifier: SignatureVerifier | None = None,
) -> AdmissionDecision:
    """Decide whether ``subject`` may be deployed. Anything but accept refuses."""
    backend = verifier if verifier is not None else CosignVerifier()
    name = subject.name
    checks: list[Check] = []

    if not policy.expected_identity:
        return _refuse(
            name,
            "no expected signer identity configured; refusing rather than "
            "accepting a signature from anyone",
            [("expected-identity-configured", False, "unset")],
        )
    checks.append(("expected-identity-configured", True, policy.expected_identity))

    if not subject.is_file():
        checks.append(("subject-present", False, f"{subject} is not a file"))
        return _refuse(name, f"subject not found: {subject}", checks)
    checks.append(("subject-present", True, str(subject)))

    actual = digest(subject)
    attested = {item.sha256 for item in attestation.subjects}
    if actual not in attested:
        checks.append(
            (
                "subject-digest-matches",
                False,
                f"artifact is {actual}, attestation covers {sorted(attested)}",
            )
        )
        return _refuse(
            name,
            "the attestation does not cover this artifact; its digest is absent "
            "from the subject list",
            checks,
        )
    checks.append(("subject-digest-matches", True, actual))

    available, detail = backend.available()
    if not available:
        checks.append(("signature-backend-available", False, detail))
        return _refuse(
            name,
            f"cannot verify the signature ({detail}); refusing rather than "
            "accepting an artifact nobody checked",
            checks,
        )
    checks.append(("signature-backend-available", True, detail))

    signed, signature_detail = backend.verify(
        subject, policy.expected_identity, policy.expected_issuer
    )
    checks.append(("signature-verified", signed, signature_detail))
    if not signed:
        return _refuse(
            name, f"signature verification failed: {signature_detail}", checks
        )

    builder = _builder_id(attestation)
    if builder != policy.expected_identity:
        checks.append(
            (
                "builder-identity-matches",
                False,
                f"provenance names {builder!r}, policy expects "
                f"{policy.expected_identity!r}",
            )
        )
        return _refuse(
            name,
            "the attestation is valid but was produced by an unexpected identity",
            checks,
        )
    checks.append(("builder-identity-matches", True, builder))

    components = _sbom_component_names(attestation)
    denied = sorted(set(components) & set(policy.denied_components))
    if denied:
        checks.append(("sbom-policy", False, f"denied components: {denied}"))
        return _refuse(name, f"SBOM contains denied components: {denied}", checks)
    checks.append(("sbom-policy", True, f"{len(components)} component(s) inspected"))

    if policy.require_sbom_components and not components:
        checks.append(
            (
                "sbom-coverage",
                False,
                "the SBOM lists no components; this generator does not perform "
                "ecosystem-aware resolution",
            )
        )
        return _refuse(
            name,
            "policy requires a component inventory and the SBOM has none",
            checks,
        )

    return AdmissionDecision(
        decision=Decision.ACCEPT,
        reason="signature, provenance identity and SBOM policy all satisfied",
        subject=name,
        asserted_identity=policy.expected_identity,
        checks=tuple(checks),
    )


def load_attestation(provenance_path: Path, sbom_path: Path) -> AttestationSet:
    """Load both documents, refusing if either is missing or malformed."""
    import json

    from pipeline_provenance.model import Subject

    def _read(path: Path, label: str) -> dict[str, Any]:
        if not path.is_file():
            raise ValueError(f"{label} not found at {path}; the set is atomic")
        try:
            loaded = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            raise ValueError(f"{label} at {path} is not valid JSON: {error}") from error
        if not isinstance(loaded, dict):
            raise ValueError(f"{label} at {path} is not an object")
        return loaded

    provenance_document = _read(provenance_path, "provenance")
    sbom_document = _read(sbom_path, "SBOM")

    raw_subjects = provenance_document.get("subject")
    if not isinstance(raw_subjects, list) or not raw_subjects:
        raise ValueError("provenance names no subject; it attests to nothing")

    subjects = tuple(
        Subject(name=str(item["name"]), sha256=str(item["digest"]["sha256"]))
        for item in raw_subjects
        if isinstance(item, dict)
    )
    return AttestationSet(
        subjects=subjects,
        provenance=provenance_document,
        sbom=sbom_document,
    )
