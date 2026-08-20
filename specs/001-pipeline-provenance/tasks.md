# Tasks: Pipeline Provenance v0.1.0

**Input**: [spec.md](spec.md), [plan.md](plan.md)
**Tests**: required. Every task below carries unit and end-to-end coverage;
tasks touching the HTML report carry browser coverage. This is not optional here
— see the definition of done in [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Format

`[ID] [P?] [Story] Description → branch`

- **[P]** — parallelisable: no unmet dependency and no file overlap with another
  **[P]** task in the same group.
- **[Story]** — the user story from `spec.md` this serves.
- Each task is one `feature/*` branch and one `--no-ff` merge.

---

## Phase 1 — Setup

**Purpose**: the repository builds, lints and type-checks before any rule exists.

- [x] **T001** Python package skeleton, `pyproject.toml`, `ppv` entry point,
      `uv` lockfile → `feature/package-skeleton`
- [x] **T002** [P] Lint and type configuration: `ruff`, `mypy --strict`,
      `pytest` markers `security` and `demo` → `feature/lint-and-type-config`
- [x] **T003** [P] CI workflow with every gate blocking: lint, type check, unit
      tests, `pip-audit`, `bandit`, `semgrep`, `gitleaks`, `trivy fs`, plus a
      separate adversarial step that fails on zero collected tests or any skip
      → `feature/ci-gates`

**Checkpoint**: `make check` is green on an empty implementation. ✅ landed 2026-08-20, together with a seeded adversarial corpus asserting this repository satisfies the invariants it sells.

---

## Phase 2 — Foundational (blocking)

**Purpose**: the shared vocabulary. Nothing else can start.

- [x] **T004** [N1] `model.py` — `Reference`, `Finding`, `AuditResult`,
      `AttestationSet`, `AdmissionDecision`; schema version constant; the
      `verified | unverified` assessment state as a required field
      → `feature/result-model`
- [x] **T005** [N1] JSON Schema for `AuditResult`, and a test asserting every
      renderer output validates against it → `feature/result-schema`

**Checkpoint**: the result contract is fixed. ✅ landed 2026-08-20.

---

## Phase 3 — User Story 1: Audit an existing repository (P1) 🎯 MVP

**Goal**: `ppv audit <path>` produces a scored, recognisable finding list.
**Independent test**: fixture repositories with known defects; assert the finding
set matches exactly by ID and location.

### Tests

- [x] **T006** [P] [US1] Fixture repositories: `naive`, `partial`, `hardened`,
      `invalid-yaml`, `no-workflows`, `monorepo` → `feature/audit-fixtures`
- [x] **T007** [P] [US1] Unit tests for every edge case listed in `spec.md`
      → `feature/audit-edge-case-tests`

### Implementation

- [x] **T008** [N2] [US1] `discovery.py` — locate workflows, composite actions,
      lockfiles and image references; carry file and line through
      → `feature/reference-discovery`
- [x] **T009** [P] [N3] [US1] Rule `i1_pinning` — FR-001; dangling-pin case
      → `feature/rule-pinning`
- [x] **T010** [P] [N3] [US1] Rule `i2_least_privilege` — FR-002, FR-003;
      effective vs declared scope; privileged triggers
      → `feature/rule-least-privilege`
- [x] **T011** [P] [N3] [US1] Rule `i3_provenance` — FR-004; admission-point
      discovery; `unverified` when none is discoverable
      → `feature/rule-provenance-coverage`
- [x] **T012** [P] [N3] [US1] Rule `i4_egress` — FR-014, FR-015; unenforceable
      environments reported as such → `feature/rule-egress`
- [x] **T013** [N4] [US1] `cli.py` — `audit`, `doctor`; exit codes per FR-009;
      offline by default, `--remote` gated on an explicit token
      → `feature/audit-cli`
- [x] **T014** [P] [N5] [US1] JSON and SARIF renderers → `feature/renderers-json-sarif`
- [x] **T015** [P] [N5] [US1] Self-contained HTML report, no external assets
      → `feature/renderer-html`
- [x] **T016** [N12] [US1] Browser suite: renders offline, findings navigable,
      score matches JSON, finding list keyboard-reachable
      → `feature/html-report-browser-tests`
- [x] **T017** [N12] [US1] End-to-end CLI suite against every fixture, asserting
      full documents and exit codes → `feature/audit-e2e-suite`

**Checkpoint**: US1 ships on its own. The MVP is releasable here. ✅ landed 2026-08-20.

---

## Phase 4 — User Story 2: Adopt the hardened pipeline (P2)

**Goal**: the reusable workflow fails closed on the four invariants.
**Independent test**: a fixture repository with an unpinned action fails at the
policy gate before any third-party step runs.

- [ ] **T018** [N9] [US2] Policy gate job — FR-010, FR-011, FR-012; reports all
      violations in one run → `feature/policy-gate`
- [ ] **T019** [N10] [US2] Hermetic build job — FR-013; no ambient credentials
      → `feature/hermetic-build`
- [ ] **T020** [N11] [US2] Egress default-deny with declared allowlist, applied
      before third-party steps — FR-014, FR-015 → `feature/egress-policy`
- [ ] **T021** [US2] Package as a reusable workflow plus composite action, with a
      documented migration path → `feature/reusable-workflow-packaging`
- [ ] **T022** [US2] End-to-end workflow tests: gate ordering, all-violations
      reporting, unenforceable-environment reporting
      → `feature/pipeline-e2e-tests`

**Checkpoint**: US1 and US2 both work independently.

---

## Phase 5 — User Story 3: Refuse an unattested artifact (P2)

**Goal**: nothing deploys without a valid attestation from the expected identity.
**Independent test**: valid / absent / wrong-identity attestation → accept /
refuse / refuse.

- [ ] **T023** [P] [N6] [US3] SLSA provenance emitter — in-toto statement,
      builder identity, resolved dependencies → `feature/slsa-provenance-emitter`
- [ ] **T024** [P] [N7] [US3] CycloneDX SBOM emitter → `feature/sbom-emitter`
- [ ] **T025** [US3] Atomic attestation set — FR-017, a build producing one
      document without the other fails → `feature/atomic-attestation-set`
- [ ] **T026** [N8] [US3] Keyless signing bound to the workflow identity
      → `feature/keyless-signing`
- [ ] **T027** [N8] [US3] Admission verifier — FR-018, FR-019; no permissive
      default; refuses when the transparency log is unreachable
      → `feature/admission-verifier`
- [ ] **T028** [US3] Build-time verification emitted as advisory and labelled
      as such — FR-020 → `feature/advisory-build-time-check`
- [ ] **T029** [US3] End-to-end verification suite across the three cases
      → `feature/verification-e2e-suite`

**Checkpoint**: US1, US2 and US3 independently functional.

---

## Phase 6 — User Story 4: See the attack fail (P3)

**Goal**: the demonstration, reproducible and blocking.
**Independent test**: collector receives the token in the naive run and nothing
in the hardened run.

- [ ] **T030** [US4] Deliberately malicious third-party action and a throwaway
      collector, confined to the demo sandbox → `feature/demo-malicious-action`
- [ ] **T031** [US4] Naive pipeline, and the assertion that the attack
      **succeeds** against it — FR-021 → `feature/demo-naive-pipeline`
- [ ] **T032** [US4] Hardened pipeline run: blocked at the gate; and the
      allowlisted-and-pinned variant blocked by three separate named controls
      → `feature/demo-hardened-pipeline`
- [ ] **T033** [US4] Demonstration as a blocking CI step, failing on zero
      collected tests or any skip — FR-022, FR-026
      → `feature/demo-blocking-ci-step`

**Checkpoint**: every claim in the README has a run behind it.

---

## Phase 7 — Measurement and release

- [ ] **T034** [N14] Benchmark harness, offline by default: SC-001, SC-002,
      SC-004, SC-008 → `feature/benchmark-harness`
- [ ] **T035** [N14] Public-repository finding distribution, aggregate only,
      no project named — SC-003 → `feature/public-corpus-study`
- [ ] **T036** [N15] README: thesis, architecture, invariants with enforcement
      points, adversarial proof, measured results with per-row caveats, and the
      Limitations section — FR-024, FR-025 → `feature/readme-results`
- [ ] **T037** [N15] Release v0.1.0: CycloneDX SBOM generated in CI and attached,
      artifacts signed with cosign, tagged → `feature/release-v0-1-0`

---

## Dependencies

- Phase 1 → Phase 2 → everything.
- US1 (Phase 3) depends only on Phase 2. It is the MVP and ships alone.
- US2 (Phase 4) depends only on Phase 2; independent of US1.
- US3 (Phase 5) depends on US2 producing artifacts.
- US4 (Phase 6) depends on US2 and US3.
- Phase 7 depends on everything it measures.

Within a story: fixtures and tests before implementation; discovery before rules;
rules before CLI and renderers; renderers before the browser suite.

## Parallel opportunities

```
after T005:   T008 ‖ T018 ‖ T023 ‖ T024
after T008:   T009 ‖ T010 ‖ T011 ‖ T012
after T013:   T014 ‖ T015
```

## Exit criterion for the milestone

A malicious third-party action in a hardened pipeline cannot read a secret,
cannot reach an unlisted host, and cannot produce a deployable artifact —
demonstrated end to end, in CI, as a blocking step. And the project's own SAST
returns zero high-severity findings against itself.
