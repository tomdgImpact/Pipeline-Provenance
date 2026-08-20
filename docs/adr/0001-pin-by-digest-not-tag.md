# ADR-0001 — Pin every reference by digest, never by tag

**Status:** Accepted — 2026-08-20

## Context

A tag is a mutable pointer. `actions/checkout@v4`, `python:3.12-slim` and a
floating version range in a lockfile all describe *a name the publisher may
repoint at any time*. The code reviewed on Tuesday is not necessarily the code
executed on Thursday, and nothing in the pipeline detects the difference.

Tag pinning is widespread because it is ergonomic: patch updates arrive for
free. That ergonomic benefit is exactly the attack — an attacker who
compromises the publisher gets the same free delivery channel.

## Decision

Every executable reference in a hardened pipeline resolves to an immutable
identifier:

- Actions pinned to a full commit SHA.
- Container base images pinned by `@sha256:` digest.
- Language dependencies pinned with hashes in a committed lockfile.

Enforcement is a check in the policy gate that runs **before** any third-party
step, not a convention in a style guide. A workflow containing an unpinned
reference does not build.

## Consequences

- Updates become explicit. Someone has to look at what changed. That is the
  point, and it is the cost.
- Dependabot or Renovate becomes load-bearing rather than optional, because
  without automation the pinned set rots.
- Readability suffers. `actions/checkout@08c6903` says less to a human than
  `@v4`. Mitigated by a comment carrying the human-readable version alongside
  the digest — a comment cannot be repointed by the publisher.
- Pinning preserves whatever was first resolved, including a mistake. It is an
  integrity control, not an identity control. See threat model T-03 and T-04.

## Alternatives rejected

- **Tag pinning plus allowlisting trusted publishers.** Reduces the population
  of possible attackers; does nothing about a compromised trusted publisher,
  which is the realistic case.
- **Vendoring third-party actions into the repository.** Immutable, but shifts
  the entire maintenance and patching burden onto us, and reviewers stop
  reading vendored code within a month.
