"""The HTML report as an interface, in a real browser.

A change to the report with no test here is not done. Four properties are
asserted: it renders with the network denied, its numbers match the JSON it
carries, its findings are navigable, and it is reachable by keyboard.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from playwright.sync_api import Page, expect

from pipeline_provenance.model import Severity

pytestmark = pytest.mark.gui

Render = Callable[[str], Page]


def _payload(page: Page) -> dict[str, object]:
    raw = page.locator("#ppv-result").text_content()
    assert raw is not None
    return dict(json.loads(raw))


class TestRendersOffline:
    def test_the_page_loads_with_every_outbound_request_denied(
        self, render_report: Render
    ) -> None:
        page = render_report("naive")
        expect(page.locator("h1")).to_have_text("Pipeline provenance audit")
        assert page.blocked_requests == []  # type: ignore[attr-defined]

    def test_styling_survives_without_the_network(self, render_report: Render) -> None:
        """Inline CSS, so the page is readable on an air-gapped host."""
        page = render_report("naive")
        colour = page.locator("body").evaluate(
            "node => getComputedStyle(node).backgroundColor"
        )
        assert colour not in ("", "rgba(0, 0, 0, 0)")


class TestNumbersMatchTheJson:
    @pytest.mark.parametrize("fixture", ["naive", "partial", "hardened", "monorepo"])
    def test_the_finding_count_matches_the_embedded_result(
        self, render_report: Render, fixture: str
    ) -> None:
        page = render_report(fixture)
        payload = _payload(page)
        findings = payload["findings"]
        assert isinstance(findings, list)
        assert page.locator("[data-ppv-finding]").count() == len(findings)

    def test_the_confirmed_count_matches_the_embedded_result(
        self, render_report: Render
    ) -> None:
        page = render_report("naive")
        summary = _payload(page)["summary"]
        assert isinstance(summary, dict)
        expect(page.locator('[data-ppv="verified-count"]')).to_have_text(
            str(summary["verified"])
        )
        expect(page.locator('[data-ppv="unverified-count"]')).to_have_text(
            str(summary["unverified"])
        )

    def test_every_invariant_status_matches_the_embedded_result(
        self, render_report: Render
    ) -> None:
        page = render_report("monorepo")
        payload = _payload(page)
        invariants = payload["invariants"]
        assert isinstance(invariants, list)
        for report in invariants:
            card = page.locator(f'[data-ppv-invariant="{report["invariant"]}"]')
            expect(card).to_have_attribute("data-status", str(report["status"]))


class TestNavigation:
    def test_findings_are_ordered_most_severe_first(
        self, render_report: Render
    ) -> None:
        page = render_report("naive")
        order = [level.value for level in Severity]
        rendered = page.locator("[data-ppv-finding]").evaluate_all(
            "nodes => nodes.map(n => n.dataset.severity)"
        )
        assert rendered == sorted(rendered, key=order.index)

    def test_filtering_by_severity_hides_the_others(
        self, render_report: Render
    ) -> None:
        page = render_report("naive")
        page.locator('.controls button[data-filter="high"]').click()
        visible = page.locator("[data-ppv-finding]:visible")
        assert visible.count() > 0
        severities = visible.evaluate_all("nodes => nodes.map(n => n.dataset.severity)")
        assert set(severities) == {"high"}

    def test_the_all_filter_restores_every_finding(self, render_report: Render) -> None:
        page = render_report("naive")
        total = page.locator("[data-ppv-finding]").count()
        page.locator('.controls button[data-filter="high"]').click()
        page.locator('.controls button[data-filter="all"]').click()
        assert page.locator("[data-ppv-finding]:visible").count() == total

    def test_unverified_findings_are_visibly_marked(
        self, render_report: Render
    ) -> None:
        page = render_report("naive")
        marked = page.locator('[data-assessment="unverified"] .tag-unverified')
        assert marked.count() > 0
        expect(marked.first).to_have_text("unverified")


class TestKeyboardReachability:
    def test_the_first_tab_stop_skips_to_the_findings(
        self, render_report: Render
    ) -> None:
        """A reader using a keyboard should not have to walk the header."""
        page = render_report("naive")
        page.keyboard.press("Tab")
        focused = page.evaluate("() => document.activeElement.className")
        assert "skip" in focused

    def test_every_finding_is_focusable(self, render_report: Render) -> None:
        page = render_report("naive")
        tabindexes = page.locator("[data-ppv-finding]").evaluate_all(
            "nodes => nodes.map(n => n.getAttribute('tabindex'))"
        )
        assert tabindexes and all(value == "0" for value in tabindexes)

    def test_filter_buttons_report_their_pressed_state(
        self, render_report: Render
    ) -> None:
        page = render_report("naive")
        button = page.locator('.controls button[data-filter="high"]')
        expect(button).to_have_attribute("aria-pressed", "false")
        button.click()
        expect(button).to_have_attribute("aria-pressed", "true")


class TestHonestyInTheInterface:
    def test_a_clean_report_does_not_claim_more_than_it_proved(
        self, render_report: Render
    ) -> None:
        page = render_report("hardened")
        expect(page.locator('[data-ppv="no-findings"]')).to_contain_text(
            "Every invariant was assessable and passed."
        )
        expect(page.locator('[data-ppv="unverifiable"]')).to_contain_text(
            "cannot confirm the runner platform enforced it"
        )

    def test_nothing_to_audit_is_not_shown_as_a_pass(
        self, render_report: Render
    ) -> None:
        page = render_report("no-workflows")
        expect(page.locator('[data-ppv="no-findings"]')).to_contain_text(
            "has not been found compliant"
        )

    def test_the_scope_caveat_is_visible_without_interaction(
        self, render_report: Render
    ) -> None:
        page = render_report("hardened")
        expect(page.locator("footer")).to_be_visible()
        expect(page.locator("footer")).to_contain_text("four named invariants")
