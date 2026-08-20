# Requirements quality checklist — v0.1.0

Applied to [spec.md](../spec.md) before planning was approved. Each item is a
property of the specification, not of the implementation.

## Completeness

- [x] Every user story has an independent test that does not depend on another story
- [x] Every functional requirement is testable as written
- [x] Edge cases are enumerated, including the "nothing to audit" and
      "cannot assess" cases
- [x] Out-of-scope items are stated explicitly rather than left implicit
- [x] Assumptions are separated from requirements

## Clarity

- [x] No requirement uses "should", "ideally", or "where possible"
- [x] Every MUST has an observable failure condition
- [x] Terms with contested meaning — hermetic, reproducible, provenance,
      verified — are defined or deferred to an ADR
- [x] Severity and scoring semantics are defined before any score is published

## Consistency

- [x] Every invariant in the spec maps to an invariant in `docs/THREAT_MODEL.md`
- [x] Every success criterion maps to at least one functional requirement
- [x] No requirement contradicts an accepted ADR
- [x] The `unverified` state appears in the model, the renderers and the scoring

## Honesty

- [x] No success criterion is stated without its corpus and method
- [x] Residual risk in the threat model is reflected in the spec's out-of-scope list
- [x] Controls that are reported but not enforced are labelled as such
      (self-hosted runners, egress on unsupported platforms)
- [x] The spec does not claim reproducibility anywhere

## Open questions

None outstanding. Items resolved during specification:

| Question | Resolution |
|---|---|
| Should the audit tool remediate as well as report? | No for v0.1.0. Rewriting workflows makes the tool responsible for correctness it cannot verify. |
| Score a repository with no discoverable admission point as failing or unverified? | Unverified. Absence of evidence is not evidence of absence, and reporting it as failing would be a false positive on a correct setup we cannot see. |
| Name individual public repositories in the corpus study? | No. Aggregate distribution only. |
