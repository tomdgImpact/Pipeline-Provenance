"""Renderers.

Every renderer takes an :class:`~pipeline_provenance.model.AuditResult` and
returns text. None of them computes anything: if a renderer needs a number the
model does not already hold, the number belongs in the model, or the three
formats will disagree the first time one of them is changed.
"""

from __future__ import annotations

__all__ = ["json_out", "sarif_out"]
