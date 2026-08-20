# ADR-0004 — Verify at admission, not at build time

**Status:** Accepted — 2026-08-20

## Context

A natural instinct is to verify the attestation at the end of the build job:
the material is right there. But the build job is boundary B2 in the threat
model — an untrusted execution context where arbitrary third-party code runs.
A check that executes inside the context it is checking can be disabled by
whoever already controls that context.

## Decision

Verification happens at the **admission point**: the moment production accepts
an artifact. Signature, provenance predicate, expected signer identity and SBOM
policy are all evaluated there, outside the build's blast radius.

An artifact without a valid attestation is not deployable — enforced at the
admission point, not by reviewer discipline.

## Consequences

- The control cannot be removed by editing a workflow file, which is exactly
  what makes it structural rather than procedural.
- Adoption is harder. Consumers must own an admission point — an admission
  controller, a deployment gate, a registry policy. Where a team has none, the
  honest answer is that I3 is not enforced for them, and the audit tool reports
  it as such rather than scoring it green.
- Build-time verification is still emitted as advisory output, clearly labelled
  as advisory, because it shortens the feedback loop during development.

## Alternatives rejected

- **Verify in the build job.** Fast feedback, zero security value against the
  adversary the threat model names.
- **Verify in a separate trusted job in the same workflow.** Better, but still
  reachable by a contributor who can modify the workflow (ADV-3), and the
  workflow file is not the trust anchor.
