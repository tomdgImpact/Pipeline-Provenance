"""One module per invariant.

Each module exposes ``evaluate(repository) -> InvariantReport`` and nothing
else. Rules never read the network, never mutate the repository, and never
report an invariant as passing on evidence they did not gather.
"""

from __future__ import annotations

__all__ = ["base"]
