# Fixture: hardened

All four invariants satisfied. This fixture is the false-positive control: any
finding reported here is a defect in the tool, not in the fixture.

- **I1** — every action pinned to a commit SHA with a version comment; the
  container image is absent rather than unpinned; dependencies installed with
  `--require-hashes`.
- **I2** — top-level `permissions: {}`, per-job least privilege, no privileged
  trigger, `persist-credentials: false`, timeouts present.
- **I3** — the build emits a CycloneDX SBOM and a provenance attestation, and
  `deploy.yml` verifies an attestation before deployment.
- **I4** — every job declares a default-deny egress policy with an explicit
  allowlist.

Expected findings: none. Expected exit code: 0.
