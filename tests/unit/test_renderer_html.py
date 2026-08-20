"""The HTML report, asserted as a document.

Browser behaviour is covered by the Playwright suite. What is asserted here is
the property no browser can check for us: that the file has no external
references at all, so it renders identically on an air-gapped machine and tells
nobody which repository was audited.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from pipeline_provenance.audit import audit
from pipeline_provenance.model import AuditResult
from pipeline_provenance.report import html_out

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"
STAMP = "2026-08-20T00:00:00Z"
CASES = ["naive", "partial", "hardened", "invalid-yaml", "no-workflows", "monorepo"]

EXTERNAL_REFERENCE = re.compile(r"""(?:src|href)\s*=\s*["'](?!#)([^"']+)""")
REMOTE_URL = re.compile(r"https?://|//[a-z0-9.-]+\.")


def _audit(name: str) -> AuditResult:
    return audit(FIXTURES / name, generated_at=STAMP)


class TestSelfContainment:
    @pytest.mark.parametrize("fixture", CASES)
    def test_no_reference_leaves_the_document(self, fixture: str) -> None:
        document = html_out.render(_audit(fixture))
        remote = [
            reference
            for reference in EXTERNAL_REFERENCE.findall(document)
            if REMOTE_URL.search(reference)
        ]
        assert not remote, f"external references: {remote}"

    def test_no_url_appears_anywhere_in_the_document(self) -> None:
        """Including in comments and CSS, where a fetch can hide."""
        assert not REMOTE_URL.search(html_out.render(_audit("naive")))

    def test_a_restrictive_content_security_policy_is_declared(self) -> None:
        document = html_out.render(_audit("naive"))
        assert "default-src 'none'" in document


class TestPayload:
    @pytest.mark.parametrize("fixture", CASES)
    def test_the_canonical_json_is_embedded_and_parses(self, fixture: str) -> None:
        document = html_out.render(_audit(fixture))
        block = re.search(
            r'<script type="application/json" id="ppv-result">(.*?)</script>',
            document,
            re.DOTALL,
        )
        assert block is not None
        payload = json.loads(block.group(1))
        assert payload["schema_version"] == "1"

    @pytest.mark.parametrize("fixture", CASES)
    def test_the_embedded_payload_matches_the_result(self, fixture: str) -> None:
        result = _audit(fixture)
        document = html_out.render(result)
        block = re.search(
            r'<script type="application/json" id="ppv-result">(.*?)</script>',
            document,
            re.DOTALL,
        )
        assert block is not None
        assert json.loads(block.group(1)) == result.to_dict()


class TestContent:
    def test_every_finding_appears_in_the_document(self) -> None:
        result = _audit("naive")
        document = html_out.render(result)
        for finding in result.findings:
            assert f'data-ppv-finding="{finding.rule_id}"' in document

    def test_all_four_invariants_are_rendered(self) -> None:
        document = html_out.render(_audit("naive"))
        for invariant in ("I1", "I2", "I3", "I4"):
            assert f'data-ppv-invariant="{invariant}"' in document

    def test_unverified_findings_are_marked(self) -> None:
        document = html_out.render(_audit("naive"))
        assert 'data-assessment="unverified"' in document

    def test_a_clean_report_says_so_without_claiming_more(self) -> None:
        document = html_out.render(_audit("hardened"))
        assert "Every invariant was assessable and passed." in document

    def test_nothing_to_audit_is_not_rendered_as_clean(self) -> None:
        document = html_out.render(_audit("no-workflows"))
        assert "has not been found compliant" in document

    def test_the_scope_caveat_is_in_the_document(self) -> None:
        """A repository that scores well satisfies four invariants; it is not
        'secure'. That sentence ships with every report."""
        document = html_out.render(_audit("hardened"))
        assert "is not &#34;secure&#34;" in document or 'is not "secure"' in document


class TestEscaping:
    def test_repository_controlled_text_is_escaped(self, tmp_path: Path) -> None:
        """Evidence lines come from the audited repository, which is attacker
        controlled in the threat model this tool is used to investigate."""
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            "name: ci\non: push\njobs:\n  a:\n"
            '    container:\n      image: "evil<script>alert(1)</script>:tag"\n'
            "    steps:\n      - run: make\n"
        )
        document = html_out.render(audit(tmp_path, generated_at=STAMP))
        assert "<script>alert(1)</script>" not in document
        assert "&lt;script&gt;" in document
