# Adopting the hardened pipeline

Written for someone with an existing repository and no appetite for a rewrite.
The order matters: every step below is reversible, and none of them blocks a
merge until you decide it should.

## 0. See your own finding list first

```bash
git clone https://github.com/tomdgImpact/Pipeline-Provenance
uv tool install ./Pipeline-Provenance
ppv audit .
```

(The tool is not published to any package index; see
[`INSTALL.md`](INSTALL.md).)

Nothing has changed yet. Read the list. `ppv audit . --format html -o ppv.html`
produces a single self-contained file you can send to someone who does not have
the tool installed.

Expect the largest group to be I1. That is normal, and it is the cheapest one to
fix.

## 1. Pin everything, in a branch of its own

Replace every `uses: owner/repo@vN` with the commit SHA, keeping the version in
a trailing comment:

```yaml
- uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
```

Turn on Dependabot for `github-actions` in the same change. Digest pinning
without an update mechanism rots, and a rotted pin is a stale vulnerability
someone will point at later.

## 2. Declare permissions

Add `permissions: {}` at the top of every workflow, then give each job only what
it uses. Two scopes are worth knowing: `id-token: write` and
`attestations: write` mint a short-lived signing identity and cannot modify the
repository, so they are not treated as excessive scope.

Add `persist-credentials: false` to every checkout while you are in the file.

## 3. Add the egress guard

This project's own references are pinned by commit SHA for the same reason
yours are: `v0.1.0` is a pointer we could move under you, and the commit is
not.

```yaml
    steps:
      - uses: tomdgImpact/Pipeline-Provenance/.github/actions/egress-guard@27609c6e5c3896d6bb8255571c353f32160e8036 # v0.1.0
        with:
          allowed-endpoints: >
            pypi.org:443
            files.pythonhosted.org:443
```

Run it in `mode: audit` for one week to collect the endpoint list your build
actually uses, then switch to `block`. `ppv audit` will report the audit-mode
period as `I4/egress-audit-only`, correctly — it is telemetry until it blocks.

**It must be the first step of the job.** Anything before it runs unrestricted.

## 4. Turn the gate on, without blocking anyone yet

```yaml
      - uses: tomdgImpact/Pipeline-Provenance/.github/actions/policy-gate@27609c6e5c3896d6bb8255571c353f32160e8036 # v0.1.0
        with:
          fail-on: critical
```

Raise the bar as the list shrinks: `critical` → `high` → `medium` → `low`.
Moving the threshold is one line and one pull request, which is the point: the
decision to accept a class of finding is visible in history.

## 5. Emit attestations

Adopt the reusable workflow, or lift its attestation steps:

```yaml
jobs:
  build:
    uses: tomdgImpact/Pipeline-Provenance/.github/workflows/hardened-build.yml@27609c6e5c3896d6bb8255571c353f32160e8036 # v0.1.0
    with:
      allowed-endpoints: "pypi.org:443 files.pythonhosted.org:443"
      build-command: "python -m build"
      artifact-path: "dist/*"
    permissions:
      contents: read
      id-token: write
      attestations: write
```

## 6. Verify at the admission point

This is the step most teams skip, and it is the one that makes the previous five
worth doing. Until something refuses an artifact, provenance is decoration.

Verification belongs where production accepts the artifact — an admission
controller, a registry policy, a deployment gate — and **not** in the build job,
which is the untrusted context the whole design assumes is compromised
([ADR-0004](adr/0004-verify-at-admission.md)).

If you have no admission point, `ppv audit` reports I3 as `unverified` rather
than failing, because the tool cannot see a control that lives outside the
repository. That is not a pass. It is a statement that nobody checked.

## What this does not do

It does not protect you from a compromised runner host, a compromised CI
platform, or an administrator. It does not make a dangerous but allowlisted
action safe. It does not tell you whether the thing you pinned was the right
thing. See [`THREAT_MODEL.md`](THREAT_MODEL.md) section 9.
