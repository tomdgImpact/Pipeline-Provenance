# Pipeline Provenance

**Supply-chain hardening for CI/CD: four structural invariants, signed
provenance, admission-time verification, and a demonstrated compromise.**

[![ci](https://github.com/tomdgImpact/Pipeline-Provenance/actions/workflows/ci.yml/badge.svg)](https://github.com/tomdgImpact/Pipeline-Provenance/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

> **Status: v0.1.0 in development.** The threat model, the invariants, the
> specification and the gate set are in place. The implementation is landing
> phase by phase — see [`ROADMAP.md`](ROADMAP.md). **No measured results are
> published yet.** When they are, each will carry the corpus, method and date
> it was measured on. Numbers without those are not published here.

---

## The thesis

The build pipeline is the largest unaudited attack surface in most
organisations. It holds production credentials, it executes third-party code on
every push, and its output is trusted by definition — nothing downstream
re-examines an artifact that arrived from "our own CI".

A compromised third-party action, a typosquatted dependency, or a mutable tag on
a container base image gives an attacker signed, trusted, production-bound
artifacts **without ever touching production**. That is a shorter path than
attacking production directly, and it is defended far less.

The fear worth naming:

> **A third-party GitHub Action you pinned to a tag can read every secret in
> that job.**

Not because the action is malicious today. Because a tag is a mutable pointer,
and the code reviewed on Tuesday is not necessarily the code executed on
Thursday.

## Who the adversary is

Three adversaries, in increasing order of capability. None has production
access. All three reach production *through* the pipeline.

| | Adversary | What they need |
|---|---|---|
| **ADV-1** | Public dependency author | Register a name, publish a version |
| **ADV-2** | Third-party action author, or whoever compromises one | One maintainer account |
| **ADV-3** | Contributor with push access to a non-protected branch | One compromised contributor |

Explicitly **out of scope**: a compromised runner host, a compromised CI
platform, a malicious repository administrator. Every guarantee below assumes
those hold. Full statement in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## The four invariants

Each is enforced by a check, at a named point, not recommended in a style guide.

| | Invariant | Enforced at | Structural? |
|---|---|---|---|
| **I1** | **Nothing runs unpinned.** Actions pinned to commit SHAs, dependencies pinned with hashes, base images pinned by digest. | Policy gate, before any third-party step runs | Yes — an unpinned reference does not build |
| **I2** | **Secrets are scoped to the job that needs them** and unreadable by third-party steps. Explicit `permissions:`, OIDC over static keys. | Policy gate | Yes |
| **I3** | **Every artifact carries verifiable provenance, and deployment verifies it.** | Admission point, outside the build's blast radius | Yes — nothing deploys without passing it |
| **I4** | **Egress from build jobs is denied by default.** A build that suddenly talks to a new host fails rather than succeeding quietly. | Build job network policy | Yes where the runner supports it; **reported as unenforceable where it does not** |

The load-bearing design claim: **the build job is an untrusted execution
context.** Controls are placed *before* it runs, on *what it may produce*, and
at *what production accepts* — never inside it, where an attacker who already
has code execution could disable them.

## Architecture

```
source ──▶ [ policy gate ]   pinning check, permissions lint, egress policy
                 │           runs to completion before any third-party step
                 ▼
           [ hermetic build ]   no ambient credentials, allowlisted egress
                 │              UNTRUSTED EXECUTION CONTEXT
                 ▼
           [ attest ]        SLSA provenance + CycloneDX SBOM,
                 │           cosign keyless signature bound to workflow identity
                 ▼
           [ verify ]        admission-time: signature, provenance predicate,
                 │           expected signer identity, SBOM policy
                 ▼
           [ deploy ]
```

## What ships

- **A reusable, opinionated workflow** implementing all four invariants,
  installable into an existing repository with a documented migration path.
- **An audit CLI (`ppv`)** that scores an existing repository against the same
  four invariants and emits JSON, SARIF and a self-contained HTML report. It
  detects I1–I4 — not "supply-chain risk" in general — and says so.
- **The demonstration:** a deliberately malicious third-party action in a
  sandbox repository that exfiltrates the job token, running successfully
  against a naive pipeline and provably failing against the hardened one.
  Reproducible, and a blocking CI step.
- **A threat model** with trust boundaries, a fourteen-row attack table, and
  accepted residual risk stated in full.

## Adversarial proof

The attack table in the threat model is not prose: every row is a test in
`tests/security/`, and that suite runs as **its own blocking CI step**. The step
fails if the suite collects zero tests or skips one — see
[`scripts/assert_suite_ran.py`](scripts/assert_suite_ran.py). A corpus that can
silently degrade to nothing is not a control, and a green tick over an empty
selection is worse than no tick at all.

The corpus already asserts this repository satisfies the invariants it sells:
every action pinned to a commit SHA, top-level permissions empty, least
privilege per job, no `pull_request_target`, no persisted checkout credentials.
A pipeline-hardening project whose own pipeline is unpinned is an argument
against itself.

## Measured results

**Not yet published.** Phase 5 of [`ROADMAP.md`](ROADMAP.md) produces:

- Detection precision and recall on a curated fixture corpus, with the corpus
  size and date.
- False-positive rate on already-hardened repositories, stated as a number.
- Distribution of findings by invariant across public repositories, **in
  aggregate only** — no individual project is named.
- Build-time overhead added by attestation and verification, in seconds, against
  a stated baseline.
- The exfiltration demonstration: token reachable in the naive pipeline, not
  reachable in the hardened one.

Every figure will appear with its caveat. "100% detection" is a marketing claim;
"100% detection on a hand-curated corpus of *n* cases matching the current rule
set, measured on *date*" is an engineering claim. The caveat is the credential.

## Limitations

Read this section before the rest.

1. **Provenance proves where an artifact came from, never that it is correct.**
   A signed attestation for a backdoored artifact is a valid attestation.
2. **A dangerous tool that is legitimately allowlisted is still dangerous.** The
   policy gate constrains *which* code runs, not what permitted code can do.
3. **No defence against a compromised runner host or CI platform.** If the
   runner does not execute what it was given, or the platform issues dishonest
   OIDC tokens, none of these controls hold. No configuration changes that.
4. **No defence against a malicious repository administrator**, who can remove
   the required status check that makes the policy gate structural.
5. **Pinning is an integrity control, not an identity control.** A typosquatted
   package pinned on day one is faithfully preserved. See threat model T-03/T-04.
6. **Allowlisted egress is still a channel.** An attacker who can reach an
   allowlisted host can exfiltrate through it. The control raises cost; it does
   not close the category.
7. **Reproducible builds are claimed only where actually achieved**, per language
   ecosystem, and never inferred from hermeticity. See
   [ADR-0005](docs/adr/0005-reproducibility-claim.md).
8. **Self-hosted runner hardening is documented, not enforced.** The audit tool
   reports on it; it cannot remediate it.
9. **The audit tool detects the four invariants above.** A repository that
   scores well is not "secure"; it satisfies four named invariants.
10. **No third-party review.** The threat model and the corpus are the author's.

## Documentation

| Document | What it holds |
|---|---|
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Trust boundaries, STRIDE, the attack table, accepted residual risk |
| [`docs/ENGINEERING_PRINCIPLES.md`](docs/ENGINEERING_PRINCIPLES.md) | The rules a change is reviewed against |
| [`docs/adr/`](docs/adr/) | Why digest pinning, keyless signing, admission-time verification, and what reproducibility is not |
| [`specs/001-pipeline-provenance/`](specs/001-pipeline-provenance/) | Specification, plan and task graph for v0.1.0 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Delivery model, branch policy, definition of done |
| [`SECURITY.md`](SECURITY.md) | Disclosure policy, and what is explicitly not a vulnerability here |
| [`ROADMAP.md`](ROADMAP.md) | Phases with exit criteria |

## Local development

```bash
make install        # project plus development dependencies
make check          # everything CI blocks on
make test-security  # the adversarial corpus, on its own
ppv doctor          # what this installation can and cannot verify
```

`ppv doctor` names every capability it does **not** have. A tool that silently
degrades into a permissive mode is worse than one that refuses.

## Licence

Apache-2.0. The patent grant matters for tooling adopted inside other
organisations' build systems.
