# Fixture: monorepo

Many workflows, most of them fine, one of them not. This fixture defends
against an aggregate score hiding a single critical behind a majority of passes:
`api.yml` and `web.yml` are clean, `release.yml` — the one workflow that
actually publishes — is the naive one.

Planted defects, all in `release.yml`:

| Defect | Invariant | Expected rule |
|---|---|---|
| `actions/checkout@v4` — mutable tag | I1 | `I1/unpinned-action` |
| `checkout` without `persist-credentials: false` | I2 | `I2/persisted-credentials` |
| `contents: write` held by a publish job | I2 | `I2/excessive-permission` |
| No egress policy in `publish` | I4 | `I4/no-egress-policy` |
| Publishes without provenance or SBOM | I3 | `I3/no-provenance`, `I3/no-sbom` |

Expected: I1, I2 and I4 failing, findings located in `release.yml` only, exit
code 1.
