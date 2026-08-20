"""The published schema is the contract; the dataclasses are an implementation.

If these ever disagree, a consumer gating on the schema breaks silently while
every internal test still passes. So the schema validates the real object, and
the schema itself is asserted to be strict enough to catch a drift.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from pipeline_provenance import SCHEMA_VERSION
from pipeline_provenance.model import (
    Assessment,
    AuditResult,
    Finding,
    Invariant,
    InvariantReport,
    Location,
    Reference,
    ReferenceKind,
    Severity,
)

SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "audit-result.v1.schema.json"
)


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _populated_result() -> AuditResult:
    """A result exercising every optional shape the schema allows."""
    verified = Finding(
        rule_id="I1/unpinned-action",
        invariant=Invariant.I1_PINNING,
        severity=Severity.HIGH,
        title="Action referenced by tag",
        detail="A tag is a mutable pointer.",
        location=Location(".github/workflows/ci.yml", 12),
        remediation="Pin to a commit SHA.",
        evidence="uses: actions/checkout@v4",
        threat_ids=("T-02",),
    )
    unverified = Finding(
        rule_id="I3/no-admission-point",
        invariant=Invariant.I3_PROVENANCE,
        severity=Severity.MEDIUM,
        title="No admission point discoverable",
        detail="Nothing in this repository verifies an attestation.",
        location=Location(".github/workflows/ci.yml"),
        remediation="Verify at the point production accepts the artifact.",
        assessment=Assessment.UNVERIFIED,
        evidence=None,
        threat_ids=("T-12",),
    )
    return AuditResult(
        target="fixture",
        generated_at="2026-08-20T00:00:00Z",
        invariants=(
            InvariantReport(Invariant.I1_PINNING, findings=(verified,)),
            InvariantReport(Invariant.I2_LEAST_PRIVILEGE),
            InvariantReport(
                Invariant.I3_PROVENANCE,
                findings=(unverified,),
                note="no admission point discoverable",
            ),
            InvariantReport(
                Invariant.I4_EGRESS,
                assessable=False,
                note="runner platform cannot enforce egress control",
            ),
        ),
        references=(
            Reference(
                raw="actions/checkout@v4",
                kind=ReferenceKind.ACTION,
                location=Location(".github/workflows/ci.yml", 12),
            ),
        ),
        unverifiable=("egress control on this runner platform",),
        workflows_examined=(".github/workflows/ci.yml",),
    )


def test_schema_declares_the_version_the_package_emits() -> None:
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION


def test_a_populated_result_validates(validator: Draft202012Validator) -> None:
    validator.validate(_populated_result().to_dict())


def test_an_empty_result_validates(validator: Draft202012Validator) -> None:
    result = AuditResult(
        target="empty",
        generated_at="2026-08-20T00:00:00Z",
        invariants=tuple(InvariantReport(i) for i in Invariant),
    )
    validator.validate(result.to_dict())


def test_schema_rejects_an_unknown_field(validator: Draft202012Validator) -> None:
    """`additionalProperties: false` is the point.

    A consumer that silently ignores an unknown field cannot distinguish a new
    signal from a typo in the one it was gating on.
    """
    document: dict[str, Any] = _populated_result().to_dict()
    document["severity_score"] = 42
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_schema_rejects_a_finding_that_maps_to_no_threat_row(
    validator: Draft202012Validator,
) -> None:
    document = _populated_result().to_dict()
    document["findings"][0]["threat_ids"] = ["not-a-threat-id"]
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_schema_rejects_a_missing_invariant(validator: Draft202012Validator) -> None:
    """All four are always reported, passing or not."""
    document = _populated_result().to_dict()
    document["invariants"].pop()
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_schema_rejects_an_unknown_assessment_state(
    validator: Draft202012Validator,
) -> None:
    """A third state would let a renderer treat "unknown" as "fine"."""
    document = _populated_result().to_dict()
    document["findings"][0]["assessment"] = "probably-fine"
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_schema_requires_a_reason_field_on_every_invariant(
    validator: Draft202012Validator,
) -> None:
    document = _populated_result().to_dict()
    del document["invariants"][0]["note"]
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_rule_ids_are_namespaced_by_invariant(validator: Draft202012Validator) -> None:
    document = _populated_result().to_dict()
    document["findings"][0]["rule_id"] = "unpinned_action"
    with pytest.raises(ValidationError):
        validator.validate(document)
