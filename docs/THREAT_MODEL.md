# Threat model — the build pipeline as an attack surface

**Scope:** a CI/CD pipeline that builds an artifact from source and produces
something a deployment consumes. Reference platform is GitHub Actions on
hosted runners; the reasoning transfers, the enforcement points do not.

**Status:** version 1, 2026-08-20. Reviewed on every change that adds or moves
a control.

---

## 1. Why this surface

The build pipeline holds production credentials, executes third-party code on
every push, and its output is trusted by definition — nothing downstream
re-examines an artifact that arrived from "our own CI".

An attacker who reaches the pipeline gets signed, trusted, production-bound
artifacts without ever touching production. That is a shorter path than
attacking production directly, and it is defended far less.

The fear this project names: **a third-party GitHub Action you pinned to a tag
can read every secret in that job.**

---

## 2. Assets

| # | Asset | Why an attacker wants it |
|---|---|---|
| A1 | Job-scoped tokens (`GITHUB_TOKEN`, OIDC assertions) | Write to the repository, mint cloud credentials |
| A2 | Long-lived secrets present in the job environment | Direct access to registries, clouds, package indexes |
| A3 | The build output itself | Ship attacker code to production under a trusted identity |
| A4 | The signing identity and attestation path | Make malicious output indistinguishable from legitimate output |
| A5 | Build caches | Persistent, cross-run code execution |
| A6 | Source and internal dependency metadata | Reconnaissance for the next step |

## 3. Adversaries

Three, in increasing order of capability. None has production access. All three
can reach production *through* the pipeline.

| # | Adversary | Capability | Cost to mount |
|---|---|---|---|
| ADV-1 | Public dependency author | Publishes a malicious version of a package the build resolves | Low — register a name, wait |
| ADV-2 | Third-party action author, or whoever compromises one | Arbitrary code inside the job, at the privilege of the job | Low to moderate — one compromised maintainer account |
| ADV-3 | Contributor with push access to a non-protected branch | Modifies workflow files, adds steps, triggers runs | Moderate — one compromised contributor |

**Explicitly out of scope.** A compromised runner host. A compromised CI
platform. A malicious repository administrator. A compromised signing service.
Each of these invalidates every control described below, and no configuration
of this project changes that. See `SECURITY.md`.

## 4. Trust boundaries

```
                        ┌──────────────────────────────────────────────┐
   developer push ──────▶│ B1  workflow definition                     │
                        │     trusted only after the policy gate       │
                        └───────────────────┬──────────────────────────┘
                                            │
                        ┌───────────────────▼──────────────────────────┐
   third-party code ───▶│ B2  build job                                │
   (actions, deps,      │     UNTRUSTED EXECUTION CONTEXT              │
    base images)        │     assume arbitrary code runs here          │
                        └───────────────────┬──────────────────────────┘
                                            │  artifact + attestation
                        ┌───────────────────▼──────────────────────────┐
                        │ B3  attestation boundary                     │
                        │     signing identity, transparency log       │
                        └───────────────────┬──────────────────────────┘
                                            │
                        ┌───────────────────▼──────────────────────────┐
                        │ B4  admission point                          │
                        │     the ONLY place trust is granted          │
                        └───────────────────┬──────────────────────────┘
                                            │
                                       production
```

The load-bearing claim: **B2 is an untrusted execution context.** Everything
inside the build job is assumed to be attacker-controlled. Controls are
therefore placed at B1 (before untrusted code runs), at B3 (what the untrusted
context is allowed to produce), and at B4 (what production accepts) — never
inside B2, where an attacker can disable them.

## 5. Structural invariants

These are the four properties the project enforces. Each is checked, not
recommended.

| # | Invariant | Enforcement point | Failure mode if absent |
|---|---|---|---|
| I1 | **Nothing runs unpinned.** Actions pinned to immutable digests, dependencies pinned with hashes, base images pinned by digest. | Policy gate, B1 | A mutable tag is repointed; today's build runs code that did not exist at review time |
| I2 | **Secrets are scoped to the job that needs them and unreadable by third-party steps.** Explicit `permissions:` blocks, OIDC federation over static keys, no organisation-wide long-lived credentials in build jobs. | Policy gate, B1 | One compromised action reads every secret in the job |
| I3 | **Every artifact carries verifiable provenance, and deployment verifies it.** An artifact without a valid attestation is not deployable. | Admission point, B4 | Provenance is generated, never checked, and therefore decorative |
| I4 | **Egress from build jobs is denied by default.** A build that suddenly talks to a new host fails rather than succeeding quietly. | Build job network policy, B2 boundary | Exfiltration is indistinguishable from a package download |

I3 is enforced at admission and not at build time on purpose: build-time
verification runs inside the untrusted context. See ADR-0004.

## 6. STRIDE over the pipeline

| Category | Concrete instance in this system | Invariant |
|---|---|---|
| **Spoofing** | Malicious artifact presented as a legitimate build; forged or replayed attestation | I3 |
| **Tampering** | Repointed action tag; poisoned build cache; modified lockfile; mutable base image | I1 |
| **Repudiation** | No record of which source, which runner and which identity produced an artifact | I3 |
| **Information disclosure** | Secret read by a third-party step; secret exfiltrated through logs, DNS or an HTTP callback | I2, I4 |
| **Denial of service** | Cache poisoning that breaks every downstream build; dependency yanking | I1 |
| **Elevation of privilege** | `pull_request_target` on an untrusted fork granting write scope; a step minting cloud credentials beyond its need | I2 |

## 7. Attack table

Each row is a test in the adversarial corpus. `tests/security/` is the
authority; this table is the human-readable index.

| ID | Attack | Adversary | Assets | Blocked by | Residual |
|---|---|---|---|---|---|
| T-01 | Malicious third-party action reads `secrets.*` from the job environment | ADV-2 | A1, A2 | I1 + I2 | An action legitimately given a secret still has it |
| T-02 | Action tag repointed to a new commit after review | ADV-2 | A3 | I1 | None if digest pinning is enforced on every reference |
| T-03 | Dependency confusion — internal package name resolved from a public index | ADV-1 | A3 | I1 (hash pinning, index scoping) | A first-time dependency is pinned to whatever was resolved first |
| T-04 | Typosquatted dependency added in a routine change | ADV-1, ADV-3 | A3 | I1 + review | Pinning does not judge whether the name was right |
| T-05 | Build cache poisoned by a run on an untrusted branch | ADV-3 | A5 | Cache scoping, I1 | Cross-run cache remains a shared surface where enabled |
| T-06 | Mutable base image tag replaced between build and deploy | ADV-2 | A3 | I1 (digest pinning) | None |
| T-07 | Secret exfiltrated in log output, or through an error message | ADV-2 | A2 | I2 (scoping), log redaction | Redaction is best-effort against a deliberate encoder |
| T-08 | Secret exfiltrated over the network to an attacker host | ADV-2 | A1, A2 | I4 | Exfiltration through an already-allowlisted host |
| T-09 | DNS-channel exfiltration | ADV-2 | A2 | I4 (egress allowlist including resolution) | Requires egress control that covers DNS, not only HTTP |
| T-10 | `pull_request_target` workflow executing fork-controlled code with write scope | ADV-3 | A1, A3 | I2 + policy gate rule | A workflow deliberately designed to run fork code |
| T-11 | Self-hosted runner persistence across jobs | ADV-2 | A1, A2, A5 | Documented, **not enforced** | Full — the tool reports, it does not remediate |
| T-12 | Unattested artifact deployed because verification is advisory | ADV-1, ADV-2, ADV-3 | A3 | I3 at admission | An admission point that is not this one |
| T-13 | Attestation generated for the right artifact by the wrong identity | ADV-2 | A4 | I3 (identity assertion in the verifier) | Trust in the OIDC issuer itself |
| T-14 | Workflow modified to remove the policy gate | ADV-3 | all | Required status check on protected branches | Repository administrator can remove the requirement |

## 8. Controls, and where they live

| Control | Boundary | Nature |
|---|---|---|
| Pinning check — every action, dependency and image reference resolves to an immutable digest or hash | B1 | Structural. A build with an unpinned reference does not start. |
| Permissions lint — explicit least-privilege `permissions:` on every job; deny on unscoped defaults | B1 | Structural. |
| Trigger lint — `pull_request_target` and equivalent privileged triggers rejected unless annotated and reviewed | B1 | Structural. |
| Egress policy — default-deny with an allowlist declared in the workflow, applied before third-party steps run | B2 boundary | Structural where the runner supports it; reported as unenforceable where it does not. |
| Hermetic build — no ambient credentials in the build step, inputs resolved from pinned references only | B2 | Structural. |
| Attestation — SLSA provenance, CycloneDX SBOM, keyless signature bound to the workflow identity | B3 | Generative. |
| Admission verification — signature, provenance predicate, expected signer identity, SBOM policy | B4 | Structural. Nothing deploys without passing it. |
| Audit CLI — scores an existing repository against I1–I4 and emits a finding list | external | Diagnostic. Detects the four invariants, not "supply-chain risk". |

## 9. Accepted residual risk

Stated plainly, because a threat model that lists only what it solves is
marketing.

1. **Provenance proves origin, never correctness.** A signed attestation for a
   backdoored artifact is a valid attestation.
2. **Allowlisted egress is a channel.** An attacker who can reach an allowlisted
   host can exfiltrate through it. The control raises cost; it does not close
   the category.
3. **First-resolution pinning inherits whatever was resolved first.** If a
   typosquatted package is pinned on day one, pinning faithfully preserves the
   compromise. Pinning is an integrity control, not an identity control.
4. **Self-hosted runners are reported, not hardened.** T-11 is fully residual.
5. **Reproducibility is claimed per ecosystem, only where achieved.** No general
   claim of reproducible builds is made.
6. **The audit tool's coverage is exactly I1–I4.** A repository that scores well
   is not "secure"; it satisfies four named invariants.
7. **Administrator-level compromise defeats everything here**, including the
   required status checks that enforce the policy gate.

## 10. Review triggers

This document is revisited when any of the following happens:

- A new invariant is added, or an existing one changes enforcement point.
- A new adversary becomes in scope.
- A control moves from structural to procedural, or the reverse.
- An attack in the corpus starts passing.
