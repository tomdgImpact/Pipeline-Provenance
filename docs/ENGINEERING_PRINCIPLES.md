# Engineering principles

These rules are not aspirational. They are the acceptance criteria a change is
reviewed against, and a change that violates one is rejected regardless of how
well it works.

## 1. Priority order

When two of these conflict, the one on the left wins:

```
security  →  correctness  →  minimal diff  →  tests  →  maintainability
```

This ordering is deliberate. A smaller, uglier change that removes an attack
path beats a larger, cleaner change that preserves it.

## 2. Structural over procedural

A control that can be turned off by editing a configuration value, or forgotten
by an operator under deadline pressure, is not a control. Prefer designs where
the unwanted behaviour has no reachable code path at all.

> "The capability does not exist in this codebase" beats "the capability is
> disabled by default".

Every invariant in `README.md` must be defensible in those terms. If the honest
answer is "it is enforced by convention", say so in the document rather than
implying enforcement that does not exist.

## 3. Fail closed, and say so out loud

When required infrastructure is missing — no attestation, no signature, no
policy file — the system refuses to proceed and reports why. Silent degradation
into a permissive mode is a defect, not a fallback.

Every tool in this repository ships a self-report path (`ppv doctor`) that
states what it can and cannot verify in the current environment.

## 4. Adversarial tests are blocking, or they do not count

The adversarial corpus runs as its own CI step. That step fails if it collects
zero tests, and it fails if any test is skipped. A suite that can silently
degrade to nothing is not evidence of anything.

## 5. Numbers are published with their caveats, never alone

"100% detection" is a marketing claim. "100% detection on a hand-curated corpus
of 34 payloads matching the current rule set, measured on 2026-08-20" is an
engineering claim. The caveat is what makes the number worth reading.

## 6. Limitations are a mandatory deliverable

`README.md` carries a Limitations section describing precisely what this
project does not do and what it does not prove. It is written before the
benchmarks, not after, and it is never softened to make a result look better.

## 7. Traceability

Every claim in the documentation points at a file, and — where automated
coverage exists — at a test. Where no automated coverage exists, the document
states that explicitly instead of leaving the reader to assume it.

## 8. Concrete constraints

- Production threat model by default. Least privilege everywhere.
- No hardcoded secrets. Environment variables plus a committed `.env.example`
  listing every secret with no values.
- Smallest effective change. No refactors outside the task at hand.
- No heavy dependency without a written justification in an ADR.
- Targeted tests for every behaviour change, security-critical paths first.
- If something cannot be verified, say so and state what needs manual checking.
- Working language for all artifacts — code, comments, docstrings, logs,
  documentation, commit messages — is English.
