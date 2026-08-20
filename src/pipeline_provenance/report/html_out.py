"""A self-contained HTML report.

Self-contained is a security property here, not a convenience one. A report
that fetches a stylesheet leaks which host opened it and when; a report that
needs the network cannot be read on the air-gapped machine where an incident is
being worked. So the document embeds everything, and a test asserts it has no
external references at all.

The rendered page also carries the canonical JSON in a
``<script type="application/json">`` block. That is what lets the browser suite
assert the displayed numbers against the machine-readable result rather than
against a second copy of the renderer's own arithmetic.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pipeline_provenance.model import AuditResult, Severity
from pipeline_provenance.report import json_out

#: Placeholder the template carries where the JSON payload belongs. The payload
#: is substituted after rendering rather than passed through the template
#: engine, so no value in this module is ever marked safe.
PAYLOAD_PLACEHOLDER = "PPV_RESULT_PAYLOAD_PLACEHOLDER"  # noqa: S105


def _embeddable_json(result: AuditResult) -> str:
    """Serialise the result for a ``<script type="application/json">`` block.

    ``<``, ``>`` and ``&`` become JSON unicode escapes rather than HTML
    entities: the block is parsed as JSON, not as HTML, so entity-escaping it
    would corrupt the payload while unicode escapes survive both readers. It is
    also what stops a ``</script>`` inside audited repository content from
    ending the block early.

    The result is substituted into the rendered document by
    :func:`render` rather than passed through Jinja. Marking a value safe is an
    escape hatch that has to be trusted; not needing one is a property that does
    not.
    """
    payload = json_out.render(result, indent=0).strip()
    for character, escape in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026")):
        payload = payload.replace(character, escape)
    return payload


TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "report.html.j2"

_ENVIRONMENT = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(("html", "j2")),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render(result: AuditResult) -> str:
    """Render ``result`` as one HTML document with no external references."""
    findings = result.findings
    counts = Counter(finding.severity for finding in findings)
    severity_counts = [
        (level.value, counts[level]) for level in Severity if counts[level]
    ]
    target = result.target
    template = _ENVIRONMENT.get_template(TEMPLATE_NAME)
    document = template.render(
        result=result,
        findings=findings,
        summary=result.to_dict()["summary"],
        severity_counts=severity_counts,
        target=target,
        target_name=Path(target).name or target,
        result_json=PAYLOAD_PLACEHOLDER,
    )
    return document.replace(PAYLOAD_PLACEHOLDER, _embeddable_json(result))
