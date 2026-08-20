# Fixture: invalid-yaml

A workflow that does not parse. The tool must report it, and must not silently
skip the file — a scanner that ignores what it cannot read reports green on the
repository whose pipeline is most likely to be wrong.

Because none of the four invariants can be assessed for an unparsable file, all
four report `unverified` for this repository, and the parse failure also appears
in the top-level `unverifiable` list.

| Defect | Invariant | Expected rule |
|---|---|---|
| Workflow does not parse; I1 cannot be assessed | I1 | `I1/unparsable-workflow` (unverified) |
| Workflow does not parse; I2 cannot be assessed | I2 | `I2/unparsable-workflow` (unverified) |
| Workflow does not parse; I3 cannot be assessed | I3 | `I3/unparsable-workflow` (unverified) |
| Workflow does not parse; I4 cannot be assessed | I4 | `I4/unparsable-workflow` (unverified) |

Four findings for one broken file reads as verbose until you notice that four
separate checks genuinely did not run. Collapsing them into one would let three
invariants report passing on a file nobody could read.

Expected exit code: 1 — not 0, and not 2. The file exists and was examined; the
tool simply could not assess it.
