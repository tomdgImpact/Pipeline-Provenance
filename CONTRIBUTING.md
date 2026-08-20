# Contributing

## Delivery model

Work is decomposed into a dependency graph before any of it is written. Each
node in that graph is a unit of delivery small enough to be reviewed in one
sitting, with an explicit owner, explicit inputs, and explicit exit criteria.
Nodes with no unmet dependency are worked in parallel; a node is never started
before the nodes it depends on have landed.

The graph for the current milestone lives in
[`specs/001-pipeline-provenance/tasks.md`](specs/001-pipeline-provenance/tasks.md).
`ROADMAP.md` holds the phase-level view with exit criteria.

### Roles

| Role | Owns | Signs off on |
|---|---|---|
| Technical lead | The graph, priority arbitration, merge authority | Every merge to `main` |
| Pipeline engineering | Policy gate, hermetic build, workflow packaging | Workflow behaviour |
| Provenance engineering | Attestation, SBOM, signing, admission verification | Attestation format and verification logic |
| Audit tooling | The `ppv` CLI, rule set, report rendering | CLI contract and output schemas |
| Security review | Threat model, adversarial corpus, dependency and secret hygiene | Any change touching a trust boundary |
| Verification | Unit, end-to-end and interface test suites; benchmark harness | Coverage and the blocking test gates |
| Documentation | README, ADRs, threat model, limitations | Public claims |

Security review and verification hold a veto that the rest of the roles cannot
override. The technical lead can reorder work; the lead cannot waive a failing
security or verification gate.

## Branching

One unit of delivery, one branch, one merge.

```
feature/<short-kebab-name>
```

`feature/` is the only accepted prefix. Examples:

```
feature/policy-gate-pinning-check
feature/slsa-provenance-emitter
feature/audit-cli-sarif-output
```

Rules:

- Branch from the current `main`.
- A branch is merged only when the feature it carries is complete: implemented,
  tested, documented, and green in CI. Partial work does not merge behind a
  flag, and does not merge "to unblock someone".
- Merge with `--no-ff` so the branch remains legible in the history.
- Delete the branch after the merge.
- Never commit directly to `main` except for the initial skeleton.
- Rebase on `main` rather than merging `main` into the branch.

## Commits

- Imperative mood, English, one logical change per commit.
- Conventional prefixes: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`,
  `ci`, `perf`, `build`.
- The body explains *why*, not *what*. The diff already says what.
- Security-relevant commits state the attack path they close.

## Definition of done

A unit of delivery is done when all of the following hold. There is no partial
credit.

1. **Unit tests.** New behaviour is covered by the unit suite, and the suite
   passes. Security-critical branches are covered first.
2. **End-to-end tests.** The behaviour is exercised through the real entry
   point — the CLI or a real workflow run against fixture repositories — not
   only through internal functions.
3. **Interface tests where an interface exists.** The HTML audit report is
   tested in a real browser with Playwright: rendering, scoring, navigation,
   and the accessibility of the finding list. A change to the report that has
   no browser test is not done.
4. **Adversarial coverage.** If the change touches a control, the corpus gains
   a case that fails without the change and passes with it.
5. **CI green.** Every gate, including lint, type check, dependency audit,
   SAST, secret scan, filesystem scan, and the adversarial step.
6. **Documentation.** Any claim the change enables or invalidates is reflected
   in `README.md`, `docs/THREAT_MODEL.md`, or a new ADR.

## Architecture decisions

Any decision that is expensive to reverse, or that a reviewer would reasonably
question, gets a short ADR in `docs/adr/`. Four to six pages of ADRs across the
project is the target, not forty. Record the trade-off and the rejected
alternative, not just the outcome.

## Review

- Every change is reviewed against `docs/ENGINEERING_PRINCIPLES.md`.
- A reviewer who cannot reconstruct *why* a control is placed where it is
  should block the change until the ADR or threat model explains it.
- "It works" is not a review outcome. "I could not find a way around it, and
  here is what I tried" is.
