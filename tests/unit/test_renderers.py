"""Three formats, one result.

The tests that matter here are the equivalence ones. Any renderer can be made
to look right on its own; the failure mode worth defending against is two of
them quietly disagreeing about the same run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from pipeline_provenance.audit import audit
from pipeline_provenance.model import Assessment, AuditResult
from pipeline_provenance.report import json_out, sarif_out

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"
SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "audit-result.v1.schema.json"
STAMP = "2026-08-20T00:00:00Z"
CASES = ["naive", "partial", "hardened", "invalid-yaml", "no-workflows", "monorepo"]


def _audit(name: str) -> AuditResult:
    return audit(FIXTURES / name, generated_at=STAMP)


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA.read_text()))


class TestJson:
    @pytest.mark.parametrize("fixture", CASES)
    def test_output_validates_against_the_published_schema(
        self, fixture: str, validator: Draft202012Validator
    ) -> None:
        validator.validate(json.loads(json_out.render(_audit(fixture))))

    def test_output_is_byte_identical_across_runs(self) -> None:
        assert json_out.render(_audit("naive")) == json_out.render(_audit("naive"))

    def test_output_ends_with_a_newline(self) -> None:
        """So the file concatenates and diffs like every other text file."""
        assert json_out.render(_audit("naive")).endswith("\n")


class TestSarif:
    @pytest.mark.parametrize("fixture", CASES)
    def test_the_envelope_is_well_formed(self, fixture: str) -> None:
        document = json.loads(sarif_out.render(_audit(fixture)))
        assert document["version"] == "2.1.0"
        assert len(document["runs"]) == 1
        driver = document["runs"][0]["tool"]["driver"]
        assert driver["name"] == "ppv"
        assert driver["informationUri"]

    def test_every_result_references_a_declared_rule(self) -> None:
        document = json.loads(sarif_out.render(_audit("naive")))
        run = document["runs"][0]
        declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        used = {result["ruleId"] for result in run["results"]}
        assert used <= declared

    def test_critical_is_not_flattened_into_high(self) -> None:
        """SARIF has no critical level, so the distinction moves to the score
        code scanning actually sorts on. Dropping it would index a critical
        finding identically to a high one."""
        document = json.loads(sarif_out.render(_audit("naive")))
        run = document["runs"][0]
        scores = {
            rule["id"]: rule["properties"]["security-severity"]
            for rule in run["tool"]["driver"]["rules"]
        }
        assert scores["I2/privileged-trigger"] == "9.0"
        assert scores["I1/unpinned-action"] == "7.0"

    def test_unverified_findings_are_marked_in_the_message(self) -> None:
        """A reader in a code-scanning UI has no other way to tell."""
        document = json.loads(sarif_out.render(_audit("naive")))
        messages = [
            result["message"]["text"]
            for result in document["runs"][0]["results"]
            if result["properties"]["assessment"] == "unverified"
        ]
        assert messages
        assert all(text.startswith("[unverified") for text in messages)

    def test_what_could_not_be_established_survives_into_sarif(self) -> None:
        document = json.loads(sarif_out.render(_audit("hardened")))
        notifications = document["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ]
        assert any(
            "cannot confirm the runner platform enforced it" in note["message"]["text"]
            for note in notifications
        )

    def test_locations_carry_a_line_where_one_exists(self) -> None:
        document = json.loads(sarif_out.render(_audit("naive")))
        regions = [
            result["locations"][0]["physicalLocation"].get("region")
            for result in document["runs"][0]["results"]
        ]
        assert any(region is not None for region in regions)


class TestEquivalence:
    @pytest.mark.parametrize("fixture", CASES)
    def test_both_formats_report_the_same_findings(self, fixture: str) -> None:
        result = _audit(fixture)
        as_json = json.loads(json_out.render(result))
        as_sarif = json.loads(sarif_out.render(result))

        json_ids = [finding["rule_id"] for finding in as_json["findings"]]
        sarif_ids = [entry["ruleId"] for entry in as_sarif["runs"][0]["results"]]
        assert json_ids == sarif_ids

    @pytest.mark.parametrize("fixture", CASES)
    def test_both_formats_agree_on_which_findings_are_unverified(
        self, fixture: str
    ) -> None:
        result = _audit(fixture)
        as_json = json.loads(json_out.render(result))
        as_sarif = json.loads(sarif_out.render(result))

        def unverified(items: list[dict[str, Any]], key: str) -> list[int]:
            return [
                index
                for index, item in enumerate(items)
                if _assessment(item, key) == Assessment.UNVERIFIED.value
            ]

        assert unverified(as_json["findings"], "assessment") == unverified(
            as_sarif["runs"][0]["results"], "properties.assessment"
        )

    def test_the_ruleset_version_is_carried_by_both(self) -> None:
        result = _audit("naive")
        as_json = json.loads(json_out.render(result))
        as_sarif = json.loads(sarif_out.render(result))
        assert (
            as_json["ruleset_version"]
            == as_sarif["runs"][0]["properties"]["rulesetVersion"]
        )


def _assessment(item: dict[str, Any], key: str) -> str:
    node: Any = item
    for part in key.split("."):
        node = node[part]
    return str(node)
