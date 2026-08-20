#!/usr/bin/env python3
"""Fail the build unless an adversarial suite actually ran.

A test corpus that can silently collect zero tests, or skip the one case that
matters, is not a control. This asserts the opposite of what a normal test
runner asserts: that the suite was non-empty and that nothing was skipped.

Usage:
    assert_suite_ran.py <junit.xml> [minimum-tests]
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: assert_suite_ran.py <junit.xml> [minimum-tests]", file=sys.stderr)
        return 2

    report = Path(argv[1])
    minimum = int(argv[2]) if len(argv) > 2 else 1

    if not report.is_file():
        print(f"FAIL: no report at {report}; the suite did not run", file=sys.stderr)
        return 1

    root = ET.parse(report).getroot()  # noqa: S314 - CI-generated, not untrusted
    suites = root.iter("testsuite")

    total = skipped = failures = errors = 0
    for suite in suites:
        total += int(suite.get("tests", 0))
        skipped += int(suite.get("skipped", 0))
        failures += int(suite.get("failures", 0))
        errors += int(suite.get("errors", 0))

    print(f"collected={total} skipped={skipped} failures={failures} errors={errors}")

    if total < minimum:
        print(
            f"FAIL: collected {total} tests, expected at least {minimum}. "
            "An empty adversarial suite proves nothing.",
            file=sys.stderr,
        )
        return 1

    if skipped:
        print(
            f"FAIL: {skipped} test(s) skipped. Adversarial cases are never "
            "conditionally skipped; a skip is a silent gap in coverage.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
