"""Attestation: what a build emits, and what an admission point checks.

The split matters. :mod:`provenance` and :mod:`sbom` run inside the build job,
which the threat model treats as an untrusted execution context, so nothing
there is trusted by anyone. :mod:`verify` runs at the admission point, outside
that job's blast radius, and is the only place a decision is made.
"""

from __future__ import annotations

__all__ = ["provenance", "sbom", "verify"]
