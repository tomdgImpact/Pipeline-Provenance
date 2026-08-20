# ADR-0005 — What reproducibility is, and is not, being claimed

**Status:** Accepted — 2026-08-20

## Context

"Reproducible builds" is the phrase most likely to be overclaimed in this
space. Bit-for-bit reproducibility is achievable in some ecosystems with
effort, approximated in others, and impractical in several. A blanket claim
would be the fastest way to lose a senior reader.

## Decision

No general reproducibility claim is made. Instead:

- Builds are **hermetic** where the ecosystem allows it: inputs resolved only
  from pinned references, no ambient credentials, no network beyond the egress
  allowlist. Hermeticity is a property this project enforces.
- **Bit-for-bit reproducibility is claimed per ecosystem, only where it was
  actually measured**, with the measurement method stated next to the claim.
- Where reproducibility was attempted and not achieved, the README says so and
  names the source of nondeterminism.

Hermeticity and reproducibility are documented as two different properties and
never used interchangeably.

## Consequences

- The README carries a smaller claim than competing material. That is the
  intent; the caveat is the credential.
- A per-ecosystem measurement harness is required in `benchmarks/`, which is
  work that a blanket claim would have avoided.

## Alternatives rejected

- **Claiming reproducible builds because the build is hermetic.** They are not
  the same property, and conflating them is the specific error this ADR exists
  to prevent.
- **Saying nothing about reproducibility.** Readers assume it either way; the
  silence gets filled with the more generous interpretation.
