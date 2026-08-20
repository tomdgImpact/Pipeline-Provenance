# Feature Specification: Pipeline Provenance v0.1.0

**Feature Branch**: `feature/*` (one branch per task node — see `tasks.md`)
**Created**: 2026-08-20
**Status**: Approved for implementation
**Milestone**: v0.1.0

## Summary

Supply-chain hardening for CI/CD: a reusable, opinionated pipeline that enforces
four structural invariants, emits SLSA provenance and a CycloneDX SBOM signed
under a keyless identity, and refuses to deploy anything that does not verify at
admission — plus a CLI that audits an existing repository against the same four
invariants, and a reproducible demonstration in which a deliberately malicious
third-party action succeeds against a naive pipeline and provably fails against
the hardened one.

Threat model, adversaries and residual risk: [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md).

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Audit an existing repository (Priority: P1) 🎯 MVP

A platform or security engineer points the tool at a repository they already own
and receives a scored finding list they recognise as their own: which actions are
unpinned, which jobs hold more token scope than they use, which workflows can be
triggered by an untrusted fork, whether anything downstream verifies the
artifacts this repository produces.

**Why this priority**: it delivers standalone value with no adoption cost, it
requires none of the other stories, and it is the artifact that makes the rest of
the project credible to someone who has not yet changed anything.

**Independent Test**: run `ppv audit <path>` against a fixture repository with
known defects and assert the finding list matches the expected set exactly, by ID
and by location.

**Acceptance Scenarios**:

1. **Given** a repository with an action referenced by tag, **When** `ppv audit`
   runs, **Then** a finding of class `I1/unpinned-action` is reported with the
   file, line, and the resolved digest that reference currently points to.
2. **Given** a repository whose workflow declares no `permissions:` block,
   **When** `ppv audit` runs, **Then** a finding of class `I2/implicit-token-scope`
   is reported, naming the default scope in force.
3. **Given** a repository with a `pull_request_target` workflow that checks out
   fork-controlled code, **When** `ppv audit` runs, **Then** a finding of class
   `I2/privileged-trigger` is reported at severity high.
4. **Given** a fully hardened fixture repository, **When** `ppv audit` runs,
   **Then** zero findings are reported and the exit code is 0.
5. **Given** any audited repository, **When** `--format html` is requested,
   **Then** a single self-contained HTML file is produced that renders with no
   network access and contains every finding present in the JSON output.
6. **Given** an environment where an invariant cannot be assessed — for example
   no admission point is discoverable — **When** `ppv audit` runs, **Then** that
   invariant is reported as `unverified`, never as `passing`.

---

### User Story 2 — Adopt the hardened pipeline (Priority: P2)

A team installs the reusable workflow into an existing repository and their build
now fails closed on anything unpinned, runs with explicitly scoped tokens, and
cannot reach a host outside the declared allowlist.

**Why this priority**: this is the control itself. It depends on nothing but is
worth less than US1 without US1, because nobody adopts a control before they have
seen their own finding list.

**Independent Test**: run the reusable workflow against a fixture repository
containing an unpinned action and assert the run fails at the policy gate, before
any third-party step executes.

**Acceptance Scenarios**:

1. **Given** a workflow with an action pinned to a tag, **When** the hardened
   pipeline runs, **Then** the run fails at the policy gate and no third-party
   step has executed.
2. **Given** a job with no explicit `permissions:` block, **When** the hardened
   pipeline runs, **Then** the run fails with a message naming the job.
3. **Given** a build step that resolves a host absent from the egress allowlist,
   **When** the build runs, **Then** the connection is denied and the build fails
   rather than continuing.
4. **Given** a runner platform where egress control cannot be enforced, **When**
   the pipeline runs, **Then** it reports the invariant as unenforceable in this
   environment rather than claiming it.
5. **Given** an existing repository following the documented migration path,
   **When** the workflow is installed, **Then** the first run reports every
   violation at once instead of failing on the first one.

---

### User Story 3 — Refuse an unattested artifact (Priority: P2)

A deployment consumes only artifacts that carry a valid attestation from the
expected identity. Anything else is refused at the admission point, outside the
build's blast radius.

**Why this priority**: without it, provenance is generated and never checked,
which is decorative. It depends on US2 producing attestations.

**Independent Test**: present an artifact with (a) a valid attestation, (b) no
attestation, (c) a valid attestation from an unexpected identity, and assert
accept / refuse / refuse.

**Acceptance Scenarios**:

1. **Given** an artifact with a valid SLSA provenance statement and CycloneDX
   SBOM signed by the expected identity, **When** admission verification runs,
   **Then** it is accepted and the decision is logged with the asserted identity.
2. **Given** an artifact with no attestation, **When** admission verification
   runs, **Then** it is refused and the reason names the missing document.
3. **Given** an artifact whose attestation is valid but signed by an identity
   other than the expected one, **When** verification runs, **Then** it is refused.
4. **Given** no configured expected identity, **When** verification runs, **Then**
   it refuses to run at all rather than accepting anything — the verifier has no
   permissive default.
5. **Given** a build that produced provenance but no SBOM, **When** the build
   completes, **Then** the build fails; the attestation set is atomic.

---

### User Story 4 — See the attack fail (Priority: P3)

A reader watches a deliberately malicious third-party action exfiltrate a job
token from a naive pipeline, then watches the same action fail against the
hardened one — reproducibly, from a public repository, as a blocking CI job.

**Why this priority**: it converts every claim above from assertion to
demonstration. It is the centrepiece of the README and it depends on US2 and US3
existing.

**Independent Test**: run both pipelines in CI and assert the collector received
the token in the naive run and received nothing in the hardened run.

**Acceptance Scenarios**:

1. **Given** the naive pipeline, **When** the malicious action runs, **Then** the
   test collector records receipt of a job token, and the demo asserts this
   happened — a demonstration where the attack silently fails to work proves
   nothing.
2. **Given** the hardened pipeline, **When** the same action is referenced,
   **Then** the run fails at the policy gate and the action never executes.
3. **Given** the hardened pipeline with the malicious action deliberately
   allowlisted and pinned, **When** it executes, **Then** it cannot read a secret
   it was not scoped, cannot reach the collector host, and cannot produce a
   deployable artifact — three separate named controls, each demonstrated.
4. **Given** the demonstration suite, **When** it collects zero tests or skips
   one, **Then** the CI step fails.

---

### Edge Cases

- A workflow that is syntactically invalid YAML — reported as a parse finding,
  never silently skipped.
- A reusable workflow referenced from another repository — followed one level and
  reported as an unresolved external reference beyond that.
- A monorepo with dozens of workflow files — findings grouped per workflow, with
  an aggregate score that does not hide a single critical behind many passes.
- A repository with no workflows at all — reports `unverified`, exit code
  distinguishes "nothing to audit" from "audited and clean".
- An action pinned to a digest that no longer resolves — reported; a dangling pin
  is an availability problem, not an integrity one, and is scored accordingly.
- A composite action that itself references unpinned actions — followed and
  reported against the calling repository.
- Rate limiting during `--remote` — fails closed with a clear message, never
  emits a partial report labelled complete.
- Transparency log unreachable during verification — refuse, do not degrade.

---

## Requirements *(mandatory)*

### Functional Requirements

**Audit engine**

- **FR-001**: The system MUST detect every action, dependency and container
  reference in a repository's workflow definitions and classify each as pinned by
  immutable identifier or not.
- **FR-002**: The system MUST report, per job, the effective token scope and
  whether it is explicitly declared or inherited from a default.
- **FR-003**: The system MUST identify privileged triggers that expose write
  scope to fork-controlled code.
- **FR-004**: The system MUST determine whether an artifact-producing workflow
  emits provenance and an SBOM, and whether any discoverable admission point
  verifies them.
- **FR-005**: The system MUST report an invariant it cannot assess as
  `unverified`, and MUST NOT report it as passing.
- **FR-006**: The system MUST emit results as JSON, SARIF and self-contained
  HTML, all rendered from one schema-versioned result object.
- **FR-007**: The system MUST operate offline by default; network access MUST be
  explicit opt-in via flag and token.
- **FR-008**: The system MUST expose a `doctor` command reporting what it can and
  cannot verify in the current environment.
- **FR-009**: The exit code MUST distinguish: clean, findings present, nothing to
  audit, and execution error.

**Hardened pipeline**

- **FR-010**: The policy gate MUST run to completion before any third-party step
  in the same run executes.
- **FR-011**: The policy gate MUST fail the run on any unpinned reference, any
  job without an explicit least-privilege permissions declaration, and any
  unannotated privileged trigger.
- **FR-012**: The policy gate MUST report all violations found in a run, not only
  the first.
- **FR-013**: The build step MUST run without ambient long-lived credentials.
- **FR-014**: Egress from build jobs MUST be denied by default, permitted only by
  an allowlist declared in the workflow, and applied before third-party steps run.
- **FR-015**: Where the runner platform cannot enforce egress control, the
  pipeline MUST report the invariant as unenforceable in that environment.

**Attestation and verification**

- **FR-016**: Every successful build MUST emit SLSA provenance and a CycloneDX
  SBOM, signed together under one keyless identity.
- **FR-017**: A build that produces one document without the other MUST fail.
- **FR-018**: Admission verification MUST check signature validity, provenance
  predicate, expected signer identity, and SBOM policy.
- **FR-019**: Admission verification MUST have no permissive default; absent an
  expected identity it MUST refuse to run.
- **FR-020**: Verification performed inside the build job MUST be labelled
  advisory in its output.

**Demonstration**

- **FR-021**: The demonstration MUST assert that the attack succeeds against the
  naive pipeline before asserting that it fails against the hardened one.
- **FR-022**: The demonstration MUST run as a blocking CI step that fails if it
  collects zero tests or skips any.
- **FR-023**: The demonstration MUST be reproducible from a public repository
  with no private infrastructure.

**Project-wide**

- **FR-024**: Every published numeric claim MUST appear with the corpus, method
  and date it was measured on.
- **FR-025**: The README MUST carry a Limitations section stating what the
  project does not do and does not prove.
- **FR-026**: The adversarial suite MUST run as a separate blocking CI step that
  fails on zero collected tests or any skip.

### Key Entities

- **Reference** — an action, dependency or image citation: raw string, resolved
  immutable identifier if any, source file, line, pinned/unpinned verdict.
- **Finding** — invariant ID (I1–I4), rule class, severity, location, evidence,
  remediation, and an explicit `verified | unverified` assessment state.
- **AuditResult** — schema-versioned aggregate: target identity, ruleset version,
  timestamp, findings, per-invariant score, and the unverifiable list.
- **AttestationSet** — SLSA provenance statement plus CycloneDX SBOM plus the
  signature bundle binding both to one workflow identity. Atomic.
- **AdmissionDecision** — accept or refuse, the asserted identity, the policy
  version applied, and the reason. Append-only.
- **DemoRun** — pipeline variant (naive | hardened), attack ID, collector
  observation, and the named control that blocked it.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `ppv audit` reports the exact expected finding set on a curated
  fixture corpus of at least 20 repositories covering all four invariants —
  measured as precision and recall by finding ID, published with the corpus size
  and date.
- **SC-002**: False-positive rate measured on a corpus of already-hardened
  repositories, published as a number with its corpus, not omitted.
- **SC-003**: Distribution of findings by invariant across a set of public
  repositories, reported in aggregate only — no individual project is named.
- **SC-004**: Build-time overhead added by attestation and admission verification,
  in seconds, measured on a reference build and stated with its baseline.
- **SC-005**: Exfiltration demonstration reports token reachable in the naive
  pipeline and not reachable in the hardened one, as an assertion pair in CI.
- **SC-006**: A team can install the hardened workflow into an existing
  repository by following the documented migration path without reading the
  source.
- **SC-007**: The project's own SAST returns zero high-severity findings against
  itself. A security project that fails its own SAST is not shippable.
- **SC-008**: Audit of a mid-sized repository completes in under 5 seconds
  offline on a developer laptop.

---

## Assumptions

- Reference platform is GitHub Actions on hosted runners. Other platforms are
  out of scope for v0.1.0; the reasoning is documented as transferable, the
  enforcement is not claimed.
- The runner executes what it was given, and the platform issues honest OIDC
  tokens. Both are stated as out-of-scope trust assumptions in the threat model.
- Consumers adopting US3 own an admission point. Where they do not, I3 is
  reported as unenforced rather than scored as passing.
- Sigstore public infrastructure is reachable, or the log and issuer are pinned
  for offline verification.
- The audit corpus is curated and synthetic in part. This is stated wherever a
  number derived from it is published.

## Out of scope for v0.1.0

- Platforms other than GitHub Actions.
- Remediation — the audit tool reports; it does not rewrite workflows.
- Self-hosted runner hardening enforcement (documented and reported only).
- Any claim of regulatory compliance derived from these technical controls.
