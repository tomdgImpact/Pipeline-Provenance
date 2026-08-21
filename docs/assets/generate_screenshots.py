"""Regenerate the README screenshots of the HTML audit report.

Run from the repository root, inside the development environment:

    .venv/bin/python docs/assets/generate_screenshots.py

The script audits ``tests/fixtures/repos/naive`` and renders the same HTML the
``ppv audit --format html`` command writes, then photographs the top of it in
both colour schemes. Three choices in here are deliberate:

* **The fixture is copied to a fixed, neutral directory first.** The report
  prints the absolute path of the audited tree in its header, and a screenshot
  committed to a public repository should not carry the home directory of
  whoever happened to generate it. The location is fixed rather than a
  ``mkdtemp`` name so that two runs produce byte-identical headers.
* **``generated_at`` is pinned.** Otherwise every regeneration produces a
  different image for identical input, and the diff says nothing.
* **Every request leaving the page is aborted**, and the run fails if one is
  attempted. The caption in the README claims the report is self-contained; this
  is the check behind that claim rather than a hope about it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from playwright.sync_api import Browser, Route, sync_playwright

from pipeline_provenance.audit import audit
from pipeline_provenance.report import html_out

REPOSITORY = Path(__file__).resolve().parents[2]
FIXTURE = REPOSITORY / "tests" / "fixtures" / "repos" / "naive"
ASSETS = REPOSITORY / "docs" / "assets"

# Pinned so that regenerating from unchanged input yields an unchanged image.
GENERATED_AT = "2026-08-21T00:00:00Z"

# Fixed, and outside any home directory, for the reason given above. Unix only,
# which is what this project develops and builds on.
WORKSPACE = Path("/tmp/ppv-screenshot")  # noqa: S108

WIDTH = 1280
PROBE_HEIGHT = 900
# Header, the four invariant cards and the first few findings. A full-page
# capture of all thirteen findings is illegible at the width README images get.
FINDINGS_SHOWN = 3
BOTTOM_MARGIN = 12
# Keeping each file well under half a megabyte: a README should not cost a
# megabyte of images to open.
SIZE_BUDGET = 400 * 1024


def _render_report(destination: Path) -> Path:
    """Audit a neutral copy of the fixture and write the HTML report."""
    target = destination / "tests" / "fixtures" / "repos" / FIXTURE.name
    target.parent.mkdir(parents=True)
    shutil.copytree(FIXTURE, target)

    result = audit(target, generated_at=GENERATED_AT)
    report = destination / "report.html"
    report.write_text(html_out.render(result), encoding="utf-8")
    return report


def _capture(browser: Browser, report: Path, scheme: str, output: Path) -> None:
    context = browser.new_context(
        viewport={"width": WIDTH, "height": PROBE_HEIGHT},
        color_scheme=scheme,
        device_scale_factor=1,
    )
    page = context.new_page()

    blocked: list[str] = []

    def deny(route: Route) -> None:
        if route.request.url.startswith("file://"):
            route.continue_()
            return
        blocked.append(route.request.url)
        route.abort()

    page.route("**/*", deny)
    page.goto(report.as_uri())

    anchor = page.locator(".finding").nth(FINDINGS_SHOWN - 1)
    box = anchor.bounding_box()
    if box is None:  # pragma: no cover - the report always has findings here
        raise RuntimeError(f"finding {FINDINGS_SHOWN} was not laid out")
    height = round(box["y"] + box["height"] + BOTTOM_MARGIN)

    page.screenshot(
        path=output,
        full_page=True,
        clip={"x": 0, "y": 0, "width": WIDTH, "height": height},
    )
    context.close()

    if blocked:
        raise RuntimeError(f"report attempted external requests: {blocked}")

    size = output.stat().st_size
    if size > SIZE_BUDGET:
        raise RuntimeError(
            f"{output.name} is {size} bytes, over the {SIZE_BUDGET} byte budget; "
            "narrow the capture rather than re-encoding it"
        )
    print(f"wrote {output.relative_to(REPOSITORY)} ({size} bytes, {height}px tall)")


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(WORKSPACE, ignore_errors=True)
    try:
        report = _render_report(WORKSPACE)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            for scheme in ("light", "dark"):
                _capture(browser, report, scheme, ASSETS / f"report-{scheme}.png")
            browser.close()
    finally:
        shutil.rmtree(WORKSPACE, ignore_errors=True)


if __name__ == "__main__":
    main()
