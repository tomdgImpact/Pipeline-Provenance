# Fixture repositories

Minimal repositories with known defects, used as the ground truth for the audit
suite. Each carries an `expected.json` listing exactly the findings the tool
must report, by ID and location — the assertion is equality, not containment,
so a new false positive fails the build.

Planned set (T006): `naive`, `partial`, `hardened`, `invalid-yaml`,
`no-workflows`, `monorepo`.
