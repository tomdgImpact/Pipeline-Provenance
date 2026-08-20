# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories on this repository
("Report a vulnerability"). Do not open a public issue for an unfixed defect.

Include: affected version or commit, environment, a minimal reproduction, and
the impact you believe it has. If you have a proof of concept that touches a
third party, describe it rather than running it.

Expect an acknowledgement within 5 working days and an assessment within 15.
Coordinated disclosure at 90 days, earlier if a fix ships sooner. Credit is
given unless you ask otherwise.

## Supported versions

The most recent tagged release, and `main`. There are no backports to earlier
tags before 1.0.0.

## What is explicitly not a vulnerability here

This project is a set of controls for build pipelines. The following are known,
documented properties rather than defects, and reports about them will be
closed with a pointer to this section:

- **A dangerous tool that is legitimately on an allowlist is still dangerous.**
  The policy gate constrains *which* actions and dependencies run, not what a
  deliberately permitted one is capable of.
- **Provenance proves origin, never correctness.** A signed attestation for a
  malicious artifact is a valid attestation. The control tells you where the
  artifact came from; it does not tell you the artifact is safe.
- **A compromised runner host or a compromised CI platform is out of scope.**
  Every guarantee here assumes the runner executes what it was given and the
  platform issues honest OIDC tokens. If either assumption fails, none of the
  controls hold, and no configuration of this project changes that.
- **A malicious operator with write access to protected branches and
  organisation secrets is out of scope.** The threat model addresses the
  contributor, the dependency author and the action author, not the
  administrator.
- **Self-hosted runner hardening is documented, not enforced.** The audit tool
  reports on it; it cannot fix it.
- **Reproducible builds are claimed only where they were actually achieved**,
  per language ecosystem, and stated as such in `README.md`.

`docs/THREAT_MODEL.md` states the trust boundaries and the accepted residual
risk in full. Read it before filing.
