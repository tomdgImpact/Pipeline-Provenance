# Architecture decision records

Short records of decisions that are expensive to reverse or that a reviewer
would reasonably question. Each states the trade-off and the rejected
alternative, not only the outcome.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-pin-by-digest-not-tag.md) | Pin every reference by digest, never by tag | Accepted |
| [0002](0002-keyless-signing.md) | Keyless signing over managed key material | Accepted |
| [0003](0003-provenance-and-sbom-pair.md) | SLSA provenance and CycloneDX SBOM as one attestation set | Accepted |
| [0004](0004-verify-at-admission.md) | Verify at admission, not at build time | Accepted |
| [0005](0005-reproducibility-claim.md) | What reproducibility is, and is not, being claimed | Accepted |
| [0006](0006-audit-tool-language-and-shape.md) | Audit tool as a Python CLI with machine-readable output | Accepted |

Format: context, decision, consequences, alternatives rejected. One page each.
