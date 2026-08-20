# Fixture: partial

The common intermediate state: someone did the pinning work, and stopped there.
This fixture exists to prove the tool does not treat "pinned" as "hardened".

Planted defects:

| Defect | Invariant | Expected rule |
|---|---|---|
| `setup-python` pinned by SHA with no version comment | I1 | `I1/missing-version-comment` |
| Job holds `contents: write` it does not use | I2 | `I2/excessive-permission` |
| Produces an artifact, emits no provenance | I3 | `I3/no-provenance` |
| Produces an artifact, emits no SBOM | I3 | `I3/no-sbom` |
| Nothing verifies an attestation | I3 | `I3/no-admission-verification` (unverified) |
| No egress policy declared | I4 | `I4/no-egress-policy` |

Deliberately clean: every action pinned to a commit SHA, dependencies installed
with `--require-hashes`, top-level default-deny, `persist-credentials: false`,
job timeout present.

Expected exit code: 1.
