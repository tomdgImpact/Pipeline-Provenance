"""Browser fixtures.

The browser is launched with routing that **aborts every request leaving the
page**. That is not paranoia about test flakiness: it is the assertion. If the
report ever grows an external reference, these tests fail rather than silently
passing on a machine that happened to have network access.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from playwright.sync_api import Browser, Page, Route, sync_playwright

from pipeline_provenance.audit import audit
from pipeline_provenance.report import html_out

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"
STAMP = "2026-08-20T00:00:00Z"


@pytest.fixture(scope="session")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch()
        yield instance
        instance.close()


@pytest.fixture
def report_page(browser: Browser, tmp_path: Path) -> Iterator[Page]:
    """A page factory bound to a hard offline policy."""
    page = browser.new_page()
    blocked: list[str] = []

    def deny(route: Route) -> None:
        if route.request.url.startswith("file://"):
            route.continue_()
            return
        blocked.append(route.request.url)
        route.abort()

    page.route("**/*", deny)
    page.blocked_requests = blocked  # type: ignore[attr-defined]
    yield page
    page.close()


@pytest.fixture
def render_report(report_page: Page, tmp_path: Path) -> object:
    def _render(fixture: str) -> Page:
        result = audit(FIXTURES / fixture, generated_at=STAMP)
        path = tmp_path / f"{fixture}.html"
        path.write_text(html_out.render(result), encoding="utf-8")
        report_page.goto(path.as_uri())
        return report_page

    return _render
