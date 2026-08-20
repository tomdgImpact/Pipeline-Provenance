# Changelog

Dates are the date the work landed. Figures are only comparable against the
ruleset version recorded beside them.

## v0.1.0 — 2026-08-20

First release. Four structural invariants, enforced and measured.

### Added

- **`ppv audit`** — offline static audit of a repository against I1–I4, with
  `text`, `json`, `sarif` and self-contained `html` output rendered from one
  schema-versioned result object. Exit codes distinguish *assessed and clean*,
  *findings*, *nothing to audit*, and *error*.
- **`ppv gate`** — the same rules as a blocking CI gate. Reports every violation
  in one run, and refuses to pass on checks it could not complete unless
  `--allow-unverified` is given deliberately.
- **`ppv verify`** — admission-time verification: signature, subject binding,
  builder identity and SBOM policy. No permissive default; an unset expected
  identity, an unavailable signature backend, or an unreachable transparency log
  all refuse.
- **`ppv doctor`** — names every capability the installation does *not* have.
- **Hardened reusable workflow** and the `egress-guard` / `policy-gate`
  composite actions, with a documented migration path in `docs/MIGRATION.md`.
- **Attestation emitters** — SLSA in-toto provenance and CycloneDX SBOM, atomic
  by construction: `AttestationSet` refuses to exist with one document missing.
- **The demonstration** — three acts, blocking in CI, asserting that the attack
  succeeds against a naive pipeline before asserting that it fails against the
  hardened one.
- **Benchmarks** — detection measured against hand-declared intent, audit
  performance, and an aggregate invariant distribution across public
  repositories. Raw output committed under `benchmarks/published/`.

### Measured

- Detection: precision 1.0, recall 1.0 across 30 declared defects in 6 fixtures;
  0 false positives on the 2 clean fixtures. Ruleset 2026.08.1.
- Public sample: 14 projects, 101 workflow files. 14/14 fail I1, I2 and I4;
  10/14 fail I3.
- Audit of this repository: 28.8 ms median, against a 5 s budget.

### Known limitations

Provenance proves origin, never correctness. A dangerous but allowlisted action
is still dangerous. A compromised runner host, CI platform or repository
administrator defeats everything here. I4 is assessed by declaration — the tool
cannot confirm the platform enforced it. Remote reference resolution
(`--remote`) is not implemented and refuses rather than degrading. Full list in
the README.
