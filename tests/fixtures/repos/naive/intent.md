# Fixture: naive

Every invariant violated, in the shape they usually appear together: a pipeline
someone wrote to get a build working, with no adversary in mind.

Planted defects:

| Defect | Invariant | Expected rule |
|---|---|---|
| `actions/checkout@v4` — mutable tag | I1 | `I1/unpinned-action` |
| `actions/setup-python@v5` — mutable tag | I1 | `I1/unpinned-action` |
| `actions/upload-artifact@v4` — mutable tag | I1 | `I1/unpinned-action` |
| `python:3.12-slim` container without digest | I1 | `I1/unpinned-image` |
| `requirements.txt` with no hashes and no lockfile | I1 | `I1/unhashed-dependencies` |
| No top-level `permissions` block | I2 | `I2/no-default-deny` |
| Job `build` inherits the default token scope | I2 | `I2/implicit-token-scope` |
| `pull_request_target` checking out the fork head | I2 | `I2/privileged-trigger` |
| `checkout` without `persist-credentials: false` | I2 | `I2/persisted-credentials` |
| Produces an artifact, emits no provenance | I3 | `I3/no-provenance` |
| Produces an artifact, emits no SBOM | I3 | `I3/no-sbom` |
| Nothing verifies an attestation anywhere | I3 | `I3/no-admission-verification` (unverified) |
| No egress policy declared in any job | I4 | `I4/no-egress-policy` |

Expected exit code: 1.
