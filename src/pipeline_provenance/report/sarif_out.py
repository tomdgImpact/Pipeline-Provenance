"""SARIF 2.1.0, so findings land where a security team already works.

SARIF has no "critical" level. Rather than inventing one, critical is mapped to
``error`` and the real severity is carried in ``properties.severity`` and in the
rule's ``security-severity`` score, which is what code scanning actually sorts
on. Dropping the distinction silently would make a critical finding indexed
identically to a high one.
"""

from __future__ import annotations

import json
from typing import Any

from pipeline_provenance import __version__
from pipeline_provenance.model import (
    SARIF_LEVEL,
    Assessment,
    AuditResult,
    Finding,
    Severity,
)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/tomdgImpact/Pipeline-Provenance"

#: Code scanning sorts on this, not on `level`.
SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}


def _rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id.replace("/", "-"),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.detail},
        "help": {
            "text": finding.remediation,
            "markdown": (
                f"**{finding.title}**\n\n{finding.detail}\n\n"
                f"**Fix:** {finding.remediation}\n\n"
                f"Invariant {finding.invariant.value} — {finding.invariant.label}."
                + (
                    "\n\nThreat model rows: " + ", ".join(finding.threat_ids)
                    if finding.threat_ids
                    else ""
                )
            ),
        },
        "defaultConfiguration": {"level": SARIF_LEVEL[finding.severity]},
        "properties": {
            "tags": [
                "supply-chain",
                f"invariant-{finding.invariant.value.lower()}",
                *finding.threat_ids,
            ],
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "precision": "high"
            if finding.assessment is Assessment.VERIFIED
            else "medium",
        },
    }


def _result(finding: Finding) -> dict[str, Any]:
    region: dict[str, Any] = {}
    if finding.location.line is not None:
        region = {"region": {"startLine": finding.location.line}}
    message = finding.detail
    if finding.assessment is Assessment.UNVERIFIED:
        message = "[unverified — this check could not be completed] " + finding.detail
    return {
        "ruleId": finding.rule_id,
        "level": SARIF_LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.path},
                    **region,
                }
            }
        ],
        "properties": {
            "severity": str(finding.severity),
            "assessment": str(finding.assessment),
            "invariant": str(finding.invariant),
            "threat_ids": list(finding.threat_ids),
        },
    }


def render(result: AuditResult, *, indent: int = 2) -> str:
    findings = result.findings
    rules = {finding.rule_id: _rule(finding) for finding in findings}
    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ppv",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": result.generated_at,
                        "toolExecutionNotifications": [
                            {
                                "level": "note",
                                "message": {"text": statement},
                            }
                            for statement in result.unverifiable
                        ],
                    }
                ],
                "results": [_result(finding) for finding in findings],
                "properties": {
                    "rulesetVersion": result.ruleset_version,
                    "schemaVersion": result.schema_version,
                    "workflowsExamined": list(result.workflows_examined),
                },
            }
        ],
    }
    return json.dumps(document, indent=indent, ensure_ascii=False) + "\n"
