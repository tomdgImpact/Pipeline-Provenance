# Roadmap

Phases are sequential; tasks inside a phase follow the dependency graph in
[`specs/001-pipeline-provenance/plan.md`](specs/001-pipeline-provenance/plan.md).
A phase is not complete until its exit criterion holds — not when its checkboxes
are ticked.

## Phase 0 — Repository skeleton ✅

- [x] Licence, ignore rules, environment template
- [x] Engineering principles, delivery model, disclosure policy
- [x] Threat model: boundaries, invariants, attack table, residual risk
- [x] Six architecture decision records
- [x] Specification, plan and task graph for v0.1.0
- [x] Package skeleton with a self-reporting `doctor`
- [x] Blocking CI gate set, every action pinned by digest
- [x] Adversarial corpus seeded with self-conformance cases

**Exit criterion:** the project's own gates run and pass against itself, and the
adversarial step fails if the suite ever collects nothing. ✅

## Phase 1 — Audit an existing repository (US1, MVP) ✅

- [x] Result model and JSON Schema (T004, T005)
- [x] Fixture repositories with exact expected findings (T006, T007)
- [x] Reference discovery with file and line provenance (T008)
- [x] Rules for the four invariants (T009–T012)
- [x] `ppv audit` with the documented exit-code contract (T013)
- [x] JSON, SARIF and self-contained HTML renderers (T014, T015)
- [x] Browser suite for the HTML report, and the CI gate that runs it (T016)
- [x] End-to-end CLI suite across every fixture (T017)

**Exit criterion:** `ppv audit` reports the exact expected finding set on the
fixture corpus — equality, not containment — and reports `unverified` rather
than passing wherever it cannot assess an invariant. ✅

## Phase 2 — Adopt the hardened pipeline (US2)

- [ ] Policy gate: pinning, permissions, trigger lint, all violations at once (T018)
- [ ] Hermetic build with no ambient credentials (T019)
- [ ] Default-deny egress with a declared allowlist (T020)
- [ ] Reusable workflow and composite action, with a migration path (T021)
- [ ] End-to-end workflow tests including gate ordering (T022)

**Exit criterion:** a workflow containing an unpinned reference fails before any
third-party step executes, and an environment that cannot enforce egress control
reports the invariant as unenforceable rather than claiming it.

## Phase 3 — Refuse an unattested artifact (US3)

- [ ] SLSA provenance and CycloneDX SBOM emitters (T023, T024)
- [ ] Atomic attestation set — one without the other fails the build (T025)
- [ ] Keyless signing bound to the workflow identity (T026)
- [ ] Admission verifier with no permissive default (T027)
- [ ] Build-time verification, labelled advisory (T028)
- [ ] End-to-end verification across valid, absent and wrong-identity cases (T029)

**Exit criterion:** the verifier refuses to run at all when no expected identity
is configured, and refuses an artifact when the transparency log is unreachable.

## Phase 4 — The demonstration (US4)

- [ ] Malicious third-party action and throwaway collector (T030)
- [ ] Naive pipeline, and the assertion that the attack succeeds against it (T031)
- [ ] Hardened pipeline: blocked at the gate, and blocked by three named
      controls when deliberately allowlisted (T032)
- [ ] Demonstration as a blocking CI step (T033)

**Exit criterion:** a malicious third-party action in a hardened pipeline cannot
read a secret, cannot reach an unlisted host, and cannot produce a deployable
artifact — demonstrated end to end, in CI, reproducibly from a public repository.

## Phase 5 — Measurement and release

- [ ] Benchmark harness, offline by default (T034)
- [ ] Aggregate finding distribution across public repositories, no project
      named (T035)
- [ ] README results section with per-row caveats and the Limitations section (T036)
- [ ] v0.1.0: SBOM generated in CI and attached, artifacts signed, tagged (T037)

**Exit criterion:** every number published in the README carries the corpus,
method and date it was measured on, and the project's own SAST returns zero
high-severity findings against itself.

## Deliberately not on this roadmap

Platforms other than GitHub Actions. Automatic remediation. Self-hosted runner
hardening enforcement. Any claim of regulatory compliance derived from these
technical controls.
