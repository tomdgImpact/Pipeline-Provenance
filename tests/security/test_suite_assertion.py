"""The control that guards the corpus is itself a control, so it is tested.

`scripts/assert_suite_ran.py` is what stops the adversarial suite from
degrading into nothing. If it ever stopped failing on an empty report, every
other test in this directory could vanish without anyone noticing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.security


def _report(tests: int, skipped: int) -> str:
    return (
        '<?xml version="1.0"?><testsuites>'
        f'<testsuite tests="{tests}" skipped="{skipped}" '
        'failures="0" errors="0"/></testsuites>'
    )


EMPTY = _report(tests=0, skipped=0)
SKIPPED = _report(tests=3, skipped=1)
CLEAN = _report(tests=3, skipped=0)


def _run(script: Path, report: Path, minimum: str = "1") -> int:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(script), str(report), minimum],
        capture_output=True,
        check=False,
    ).returncode


@pytest.fixture
def script(repo_root: Path) -> Path:
    return repo_root / "scripts" / "assert_suite_ran.py"


def test_empty_suite_fails(script: Path, tmp_path: Path) -> None:
    report = tmp_path / "empty.xml"
    report.write_text(EMPTY)
    assert _run(script, report) == 1


def test_any_skip_fails(script: Path, tmp_path: Path) -> None:
    report = tmp_path / "skipped.xml"
    report.write_text(SKIPPED)
    assert _run(script, report) == 1


def test_missing_report_fails(script: Path, tmp_path: Path) -> None:
    assert _run(script, tmp_path / "absent.xml") == 1


def test_below_minimum_fails(script: Path, tmp_path: Path) -> None:
    report = tmp_path / "clean.xml"
    report.write_text(CLEAN)
    assert _run(script, report, minimum="10") == 1


def test_non_empty_clean_suite_passes(script: Path, tmp_path: Path) -> None:
    report = tmp_path / "clean.xml"
    report.write_text(CLEAN)
    assert _run(script, report) == 0
