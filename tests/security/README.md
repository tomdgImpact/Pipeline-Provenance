# Adversarial corpus

Every test in this directory carries the `security` marker and runs as its own
blocking CI step. That step fails if the suite collects zero tests or skips one
— see `scripts/assert_suite_ran.py`.

The corpus has two halves:

- **Self-conformance.** This repository must satisfy the invariants it sells.
  A pipeline-hardening project whose own pipeline is unpinned is an argument
  against itself. These tests are written against `.github/workflows/`.
- **Attack cases.** One test per row of the attack table in
  `docs/THREAT_MODEL.md`, each asserting that a specific attack is refused by a
  specific named control. These land with the controls they exercise.

A test here never skips conditionally. If a case cannot run in an environment,
that is a gap in coverage, and the step fails rather than reporting green.
