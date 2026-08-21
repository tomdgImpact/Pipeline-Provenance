# Changelog

Dates are the date the work landed. Figures are only comparable against the
ruleset version recorded beside them.

## v0.1.1 — 2026-08-21

A security release. Everything else in it is documentation.

### Fixed

- **The reusable workflow put the signing identity within reach of the code it
  builds.** `hardened-build.yml` executed `${{ inputs.build-command }}` — the
  caller's own command — in the same job that held `id-token: write` and
  `attestations: write`. GitHub exposes `ACTIONS_ID_TOKEN_REQUEST_TOKEN` to
  every step of such a job, so that command could request the token and obtain
  an attestation for an artifact of its choosing, under this workflow's
  identity: a valid signature over something nobody here built. Threat model
  **T-13**, reachable without compromising anything, and built by our own hand.

  The build command now runs in a job holding **no write scope at all**, which
  uploads its raw output; a separate job attests it, running only actions
  pinned by digest. The signing identity is not reachable from anything the
  caller controls.

  **Anyone pinned to `27609c6e…` (v0.1.0) is running the defective workflow and
  should re-pin** — see [`docs/MIGRATION.md`](docs/MIGRATION.md). No credential
  of this project was exposed by the defect; what it exposed was every adopter's
  ability to have their own workflow identity misused by their own build script.

- The performance table in the README quoted a run from before the release
  while the committed record held another. Every published figure is now bound
  by test to the record that produced it, not only the detection figures.

- The documented adoption examples referenced this project by tag, which is the
  mutable pointer invariant I1 exists to refuse. They are pinned by commit SHA,
  and a test now enforces that on the documentation as well as on the pipeline.

- Three installation paths in the documentation did not work as written.

### Added

- **`tests/security/test_signing_identity_isolation.py`** — the fix above is
  structural, so its regression test is too. It fails if any job in any shipped
  workflow holds a signing scope while a caller-supplied input reaches
  execution, through `run:`, through a job- or step-level `env:` value, or
  through a `with:` input to one of this repository's composite actions. It
  runs in the adversarial corpus, which is a blocking CI step that fails if it
  collects nothing or skips anything. It was run against the defective workflow
  and fails there, naming the offending step.

- [`docs/COMPLIANCE_MAPPING.md`](docs/COMPLIANCE_MAPPING.md) — what the four
  invariants are, and are not, evidence for, against SLSA v1.2, NIST SSDF, the
  CRA, NIS2 and DORA. It records the SLSA assessment as **Build L2, not L3**,
  and names both requirements that stand between the two. The T-13 defect above
  was found while writing it.

- [`docs/ADOPTION_COST.md`](docs/ADOPTION_COST.md) — what each invariant costs
  to adopt, in hours and in ongoing friction, rather than only why it is worth
  adopting.

- [`docs/INSTALL.md`](docs/INSTALL.md), architecture and trust-boundary
  diagrams rendered as Mermaid, and the HTML audit report shown in the README.

### Changed

- `docs/MIGRATION.md` and the usage comment in `hardened-build.yml` now pin to
  `f9ac3f27…`. That SHA is the commit this release was cut from: a file cannot
  contain the digest of the commit that introduces it, and the trees differ
  only by this changelog, the version bump and the pin lines themselves.

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
