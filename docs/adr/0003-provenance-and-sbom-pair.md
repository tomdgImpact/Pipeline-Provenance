# ADR-0003 — SLSA provenance and CycloneDX SBOM as one attestation set

**Status:** Accepted — 2026-08-20

## Context

Two different questions get confused. *Where did this artifact come from?* is
answered by build provenance. *What is inside it?* is answered by a bill of
materials. Shipping only one leaves a verifier unable to make useful policy
decisions: provenance alone cannot answer "does this contain the vulnerable
version of that library", and an SBOM alone can be authored by anyone.

## Decision

Every build emits both, signed together as one attestation set:

- **SLSA provenance** — the builder identity, the source revision, the build
  invocation and the resolved dependencies, as an in-toto statement.
- **CycloneDX SBOM** — the component inventory of the produced artifact.

Both are signed under the same keyless identity (ADR-0002) and both are
verified at admission (ADR-0004). Neither is optional; a build that produces
one without the other fails.

## Consequences

- Admission policy can be written against either document, and against both
  together — for example "provenance from this workflow, and no component on
  the deny list".
- Two formats to keep current as their specifications move.
- SBOM quality is bounded by the generator. An SBOM that misses a vendored
  dependency is silently incomplete, and no signature makes it complete. This
  is stated in the limitations rather than papered over.

## Alternatives rejected

- **Provenance only.** Cheaper, and the common choice. Answers origin but makes
  component policy impossible, which is the question most organisations
  actually have to answer under a deadline.
- **SBOM only.** Common in compliance-driven programmes. An unsigned or
  unattested SBOM is a document, not evidence.
