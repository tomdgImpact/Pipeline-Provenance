# Implementation Plan: Pipeline Provenance v0.1.0

**Date**: 2026-08-20 | **Spec**: [spec.md](spec.md) | **Tasks**: [tasks.md](tasks.md)

## Summary

Three shipping surfaces from one analysis core: a reusable GitHub Actions
workflow enforcing four invariants, an attestation and admission-verification
path, and a `ppv` CLI that audits any repository against the same invariants and
renders JSON, SARIF and a self-contained HTML report. A fourth surface — the
adversarial demonstration — exists to prove the first three.

## Technical Context

**Language/Version**: Python 3.12
**Primary Dependencies**: `click` (CLI), `ruamel.yaml` (round-trip YAML with line
numbers, needed for finding locations), `jinja2` (HTML report), `httpx` (opt-in
remote resolution). Heavier additions require an ADR per the engineering
principles.
**Storage**: none. The tool is stateless; results are files.
**Testing**: `pytest` for unit and end-to-end, `pytest` markers `security` and
`demo` for the blocking adversarial steps, `playwright` (Python bindings) for
browser coverage of the HTML report.
**Target Platform**: developer laptop (macOS, Linux) and GitHub-hosted runners.
**Project Type**: CLI plus packaged CI workflow. Single project layout.
**Performance Goals**: SC-008 — under 5 s offline on a mid-sized repository.
**Constraints**: offline by default; no network unless `--remote` with an
explicit token; self-contained HTML with no external asset references (CSP-safe).
**Scale/Scope**: v0.1.0 targets four invariants, one platform, one milestone.

## Constitution Check

| Principle | How this plan satisfies it | Risk |
|---|---|---|
| Security before correctness | Controls placed at B1/B3/B4, never inside the build job | None identified |
| Structural over procedural | Policy gate is a required status check; admission verification has no permissive default | I4 is only structural where the runner supports egress control — reported, not claimed |
| Fail closed and say so | `unverified` is a first-class result state; `ppv doctor` self-reports | Requires discipline in every new rule |
| Adversarial tests blocking | Separate CI step, fails on zero collected or any skip | None |
| Numbers with caveats | Benchmark harness emits corpus size, method and date alongside every figure | None |
| Limitations mandatory | Written before the benchmarks, in README and threat model | None |
| Minimal diff | One analysis core, three renderers | Three formats can drift — mitigated by one result object and a schema test |

No violation requiring a Complexity Tracking entry.

## Project Structure

### Documentation (this feature)

```
specs/001-pipeline-provenance/
├── spec.md
├── plan.md
├── tasks.md
└── checklists/
    └── requirements.md
```

### Source code (repository root)

```
src/pipeline_provenance/
├── __init__.py
├── cli.py                  # ppv entry point: audit, verify, doctor
├── model.py                # Reference, Finding, AuditResult, schema version
├── discovery.py            # locate workflows, actions, lockfiles, images
├── rules/
│   ├── i1_pinning.py
│   ├── i2_least_privilege.py
│   ├── i3_provenance.py
│   └── i4_egress.py
├── attest/
│   ├── provenance.py       # SLSA in-toto statement
│   ├── sbom.py             # CycloneDX
│   └── verify.py           # admission-time verification
└── report/
    ├── json_out.py
    ├── sarif_out.py
    ├── html_out.py
    └── templates/report.html.j2

.github/workflows/
├── ci.yml                  # this project's own gates
├── hardened-build.yml      # the reusable workflow that ships
└── demo-supply-chain.yml   # naive vs hardened, blocking

policy/
├── pinning.yml
├── permissions.yml
└── egress.example.yml

tests/
├── unit/
├── e2e/                    # real CLI against fixture repositories
├── gui/                    # playwright against the HTML report
├── security/               # adversarial corpus, blocking marker
└── fixtures/repos/         # naive, partially hardened, hardened

benchmarks/                 # offline by default, reproducible harness
docs/
```

**Structure Decision**: single project. The reusable workflow and the CLI share
the rule definitions; splitting them into two repositories would duplicate the
rule set, which is the one thing that must not drift.

## Delivery graph

Nodes are units of delivery. Each becomes one `feature/*` branch and one merge.
An edge means "must land first".

```
        N1 model + schema
              │
      ┌───────┼─────────────┬─────────────────┐
      ▼       ▼             ▼                 ▼
   N2 discovery      N6 provenance      N9 policy gate
      │                  emitter          (workflow)
      ▼                    │                  │
   N3 rules I1..I4         ▼                  ▼
      │              N7 SBOM emitter    N10 hermetic build
      ├──────┐             │                  │
      ▼      ▼             ▼                  ▼
   N4 CLI  N5 renderers  N8 admission    N11 egress policy
      │      │             verifier            │
      └──┬───┘             │                   │
         ▼                 └─────────┬─────────┘
    N12 e2e + gui suites             ▼
         │                    N13 demonstration
         └──────────┬─────────────────┘
                    ▼
              N14 benchmarks
                    ▼
              N15 README + release
```

Parallelisable at any moment: `{N2, N6, N9}` after N1; `{N4, N5}` after N3;
`{N7, N11}` alongside their siblings. Security review and verification sign off
on every node; neither can be waived by resequencing the graph.

## Verification strategy

Three layers, all required by the definition of done:

1. **Unit** — rule logic against synthetic inputs, including every edge case in
   the spec. Fast, offline, no fixtures on disk where a string will do.
2. **End-to-end** — the real `ppv` binary against fixture repositories on disk,
   asserting exit codes and full output documents; and real workflow runs for
   the pipeline surfaces.
3. **Browser** — Playwright against the generated HTML report: it renders with
   no network, findings are navigable, the score matches the JSON, and the
   finding list is reachable by keyboard.

Plus the adversarial corpus as a separate blocking step, and a schema test
asserting JSON, SARIF and HTML are all derived from the same result object.

## Risks

| Risk | Mitigation |
|---|---|
| Egress control unenforceable on hosted runners for some ecosystems | Report as unenforceable rather than claim it; ADR if the position changes |
| Three output formats drift | One result object, schema version, cross-format equivalence test |
| Sigstore infrastructure dependency | Pinned log and issuer, offline verification path, documented in ADR-0002 |
| Public-repository benchmark reads as naming and shaming | Aggregate statistics only; SC-003 forbids naming individual projects |
| Scope creep into "supply-chain security" generally | The tool detects I1–I4 and says so; anything else is out of scope for v0.1.0 |
