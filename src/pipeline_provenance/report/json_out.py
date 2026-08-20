"""The canonical output. Everything else is a projection of this."""

from __future__ import annotations

import json

from pipeline_provenance.model import AuditResult


def render(result: AuditResult, *, indent: int = 2) -> str:
    """Serialise the result exactly as the published schema describes it.

    Keys are not sorted: the order in ``to_dict`` is the reading order a human
    wants, and machine consumers do not care. Two runs over the same input
    produce byte-identical output, which is what makes the end-to-end suite able
    to assert whole documents.
    """
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False) + "\n"
