# Fixture repositories

Ground truth for the audit suite. Each fixture is a minimal repository with
deliberately planted defects, and each carries an `intent.md` naming every
defect and the rule expected to catch it.

`intent.md` is written **before** the rule that detects the defect. It is the
specification the rule is implemented against, not a transcript of what the tool
happened to output — otherwise the assertion degenerates into "the tool agrees
with itself".

| Fixture | Purpose |
|---|---|
| `naive` | Every invariant violated, in the shape they usually appear together |
| `partial` | Pinned and nothing else — proves "pinned" is not read as "hardened" |
| `hardened` | The false-positive control: any finding here is a defect in the tool |
| `invalid-yaml` | A file the tool cannot read is reported, never silently skipped |
| `no-workflows` | Nothing to audit is not the same as nothing found |
| `monorepo` | An aggregate score must not hide one critical behind many passes |

The end-to-end suite (T017) adds an `expected.json` per fixture and asserts
**equality** against it, not containment, so a new false positive fails the
build.
