# Fixture: invalid-yaml

A workflow that does not parse. The tool must report it, and must not silently
skip the file — a scanner that ignores what it cannot read reports green on the
repository whose pipeline is most likely to be wrong.

Because none of the four invariants can be assessed for an unparsable file, all
four report `unverified` for this repository, each with an `unparsable-workflow`
finding carrying `assessment: unverified`, and the parse failure also appears in
the top-level `unverifiable` list.

Expected exit code: 1 — not 0, and not 2. The file exists and was examined; the
tool simply could not assess it.
