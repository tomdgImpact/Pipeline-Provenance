# ADR-0002 — Keyless signing over managed key material

**Status:** Accepted — 2026-08-20

## Context

Signing artifacts requires a private key. A long-lived signing key stored as a
CI secret is readable by every step in the job that can reach it — precisely the
adversary in the threat model (T-01). A key management service reduces exposure
but reintroduces a long-lived credential to reach the service.

The signing identity is asset A4: whoever holds it can make malicious output
indistinguishable from legitimate output.

## Decision

Sign with Sigstore keyless flow: the runner's ambient OIDC token is exchanged
for a short-lived certificate bound to the workflow identity, the signature is
recorded in a public transparency log, and the certificate expires within
minutes.

Verification asserts the **identity** — repository, workflow path, trigger and
issuer — not the possession of a key.

## Consequences

- There is no signing key to steal, rotate or accidentally commit.
- The verifier's configuration becomes the security-relevant artifact. A
  verifier that accepts any identity is worse than no verification, because it
  reads as a control. `PPV_EXPECTED_SIGNER_IDENTITY` has no default.
- A dependency on public good infrastructure (Fulcio, Rekor) is introduced,
  including its availability. Offline and air-gapped verification requires
  pinning the log and issuer explicitly, which `.env.example` exposes.
- Signing events are public. Repository and workflow names appear in a public
  transparency log. For private repositories this is an information-disclosure
  trade-off that must be made deliberately.

## Alternatives rejected

- **Long-lived key in a CI secret.** Directly defeated by T-01.
- **Cloud KMS signing.** Better than a raw key, but the credential to reach the
  KMS is still present in the job, and the audit trail lives in one vendor
  rather than a public log.
