# README assets

Two screenshots of the HTML audit report, and the script that produced them.
They exist so the top-level README shows the report instead of describing it.

| File | What it is |
| --- | --- |
| `report-light.png` | The report as a light-scheme reader sees it. The `<img>` fallback in the README. |
| `report-dark.png` | The same report under `prefers-color-scheme: dark`. |
| `generate_screenshots.py` | Regenerates both from the fixture. |

## Regenerating

From the repository root, in the development environment:

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
.venv/bin/python -m playwright install chromium

.venv/bin/python docs/assets/generate_screenshots.py
```

The script prints the byte size and pixel height of each file it writes, and
exits non-zero rather than writing an image that breaks one of the constraints
below.

## What is in the picture, and why

- **Input:** `tests/fixtures/repos/naive` — the deliberately unhardened
  repository the test suite audits. It fails all four invariants and raises
  thirteen findings, one critical, six high, six medium. Nothing in the image is
  staged: it is the output of `audit()` over that fixture, rendered by the same
  `report.html_out` template the `ppv audit --format html` command uses.
- **Crop:** header, the four invariant cards, and the first three findings, at a
  1280-pixel viewport. All thirteen findings would be a 5000-pixel image that is
  unreadable at the width a README grants it, so the capture is clipped to the
  bottom of the third finding.
- **Neutral path:** the fixture is copied to a fixed directory outside any home
  directory before it is audited. The report prints the absolute path of the
  tree it examined, and a committed screenshot should not carry the home
  directory of whoever generated it.
- **Pinned timestamp:** `generated_at` is fixed, so regenerating from unchanged
  input yields an unchanged image and a diff means a real change.
- **Offline, enforced:** every request leaving the page is aborted while the
  screenshot is taken, and the script fails if the page attempts one. The
  README caption claims the report needs no network; this is what backs it.

## Constraints these files must keep

- Under 400 KB each — a README should not cost a megabyte of images to open. If
  a capture grows past the budget, narrow the viewport or the crop. Do not
  re-encode at lower quality: the value of the image is that the finding text is
  readable.
- Both schemes regenerated together. A light-only screenshot misrepresents a
  report that is theme-aware.
- Regenerate whenever the report template, the rule set, or the `naive` fixture
  changes. A screenshot that no longer matches the tool is worse than none.

## What keeps these honest

A screenshot is a claim about the software, and it is the one kind of claim that
rots silently: change a rule, a severity or a line of the template, and the
image still looks plausible while describing a version that no longer exists.

`manifest.json` records the SHA-256 of the report these images were taken of,
along with the digest and size of each PNG and how the capture was framed.
`tests/security/test_screenshot_freshness.py` re-renders the report and fails if
that digest has moved, telling you to regenerate.

Two details make it work in CI rather than only on a laptop:

- **No pixels are compared.** Font rasterisation differs between macOS and the
  Linux runner, so a byte comparison of the PNGs would fail on every platform
  change and catch none of the changes that matter.
- **The report's own file path is replaced with a placeholder before hashing**,
  so the digest describes the report — template, rule set, fixture — and not the
  machine that rendered it.

The check needs no browser and runs in the fast adversarial job. Regenerate with
the command at the top of this file, and commit the images and the manifest in
the same change.
