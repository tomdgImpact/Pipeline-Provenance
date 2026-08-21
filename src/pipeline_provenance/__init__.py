"""Supply-chain hardening for CI/CD pipelines.

This package ships the analysis core shared by the ``ppv`` command line tool
and the reusable workflow: the four structural invariants described in
``docs/THREAT_MODEL.md`` are defined once and enforced from both surfaces.
"""

__all__ = ["__version__", "SCHEMA_VERSION"]

__version__ = "0.1.1"

#: Version of the ``AuditResult`` document produced by this package. Consumers
#: gate on this, not on ``__version__``.
SCHEMA_VERSION = "1"
