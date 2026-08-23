"""The README screenshots must show the report the code actually produces.

A screenshot is a claim about the software, and it is the one kind of claim
that rots silently: change a rule, a severity, or a line of the template, and
the image keeps looking plausible while describing a version that no longer
exists. Nothing in the test suite would notice, and a reader has no way to tell.

The check deliberately does **not** compare pixels. Font rasterisation differs
between macOS and the Linux CI runner, so a byte comparison of the PNGs would
fail on every platform change and pass on none of the changes that matter. What
is compared is the digest of the report the screenshots were taken of, recorded
in ``docs/assets/manifest.json`` at generation time. If the report changes, the
images are stale, and this fails — on any platform, without a browser.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

pytestmark = pytest.mark.security

REPOSITORY = Path(__file__).resolve().parents[2]
ASSETS = REPOSITORY / "docs" / "assets"
MANIFEST = ASSETS / "manifest.json"
GENERATOR = ASSETS / "generate_screenshots.py"

REGENERATE = (
    "Regenerate them:\n"
    "    .venv/bin/python docs/assets/generate_screenshots.py\n"
    "then commit the images and the updated manifest together."
)


def _load_generator() -> ModuleType:
    """Import the generator by path; `docs/assets` is not a package."""
    specification = importlib.util.spec_from_file_location(
        "ppv_generate_screenshots", GENERATOR
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load_generator()


@pytest.fixture(scope="module")
def manifest() -> dict[str, Any]:
    assert MANIFEST.is_file(), f"no screenshot manifest at {MANIFEST}"
    return dict(json.loads(MANIFEST.read_text()))


def test_the_screenshots_show_the_report_the_code_produces_today(
    generator: ModuleType, manifest: dict[str, Any], tmp_path: Path
) -> None:
    """The check that closes the gap.

    Rendering is cheap and needs no browser, so this runs in the fast
    adversarial job rather than behind the browser gate.
    """
    current = generator.digest(generator.canonical_report_html(tmp_path).encode())
    assert current == manifest["report_sha256"], (
        "The HTML audit report has changed since the README screenshots were "
        "taken, so the images now show a version of the report that no longer "
        "exists.\n" + REGENERATE
    )


def test_every_committed_image_matches_the_manifest(
    manifest: dict[str, Any],
) -> None:
    """Catches an image replaced without regenerating the manifest — which
    would otherwise restore exactly the drift this file exists to prevent."""
    for name, recorded in manifest["images"].items():
        image = ASSETS / name
        assert image.is_file(), f"{name} is in the manifest and not on disk"
        generator = _load_generator()
        assert generator.digest(image.read_bytes()) == recorded["sha256"], (
            f"{name} does not match the manifest.\n" + REGENERATE
        )
        assert image.stat().st_size == recorded["bytes"], name


def test_the_manifest_describes_every_image_in_the_directory(
    manifest: dict[str, Any],
) -> None:
    """An image added without a manifest entry is an unguarded claim."""
    on_disk = {path.name for path in ASSETS.glob("*.png")}
    assert on_disk == set(manifest["images"]), (
        "images and manifest disagree about which screenshots exist"
    )


def test_the_readme_shows_only_images_the_manifest_covers(
    manifest: dict[str, Any],
) -> None:
    readme = (REPOSITORY / "README.md").read_text()
    referenced = {
        name for name in manifest["images"] if f"docs/assets/{name}" in readme
    }
    assert referenced, "the README references none of the recorded screenshots"


def test_the_fixture_the_screenshots_were_taken_of_still_exists(
    manifest: dict[str, Any],
) -> None:
    fixture = REPOSITORY / manifest["fixture"]
    assert fixture.is_dir(), (
        f"{manifest['fixture']} is gone; the screenshots describe a fixture "
        "that no longer exists"
    )


def test_the_manifest_records_how_the_capture_was_framed(
    manifest: dict[str, Any], generator: ModuleType
) -> None:
    """Framing is part of what the image claims. A capture that silently starts
    showing one finding instead of three is a different claim."""
    assert manifest["viewport_width"] == generator.WIDTH
    assert manifest["findings_shown"] == generator.FINDINGS_SHOWN
    assert manifest["generated_at"] == generator.GENERATED_AT
