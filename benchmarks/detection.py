"""SC-001 and SC-002: detection quality against hand-declared intent.

The denominator is the defect table in each fixture's ``intent.md``, written
before the rule that finds it. Measuring against ``expected.json`` — which the
tool generated — would establish only that the tool agrees with itself, which is
the failure mode most detection benchmarks quietly have.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pipeline_provenance import __version__
from pipeline_provenance.audit import audit
from pipeline_provenance.model import RULESET_VERSION

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "repos"
STAMP = "2026-08-20T00:00:00Z"

#: Rule ids inside a backticked cell of the declared-defect table.
DECLARED = re.compile(r"`(I[1-4]/[a-z0-9-]+)`")


@dataclass(frozen=True)
class Measurement:
    fixture: str
    declared: Counter[str]
    reported: Counter[str]

    @property
    def true_positives(self) -> int:
        return sum((self.declared & self.reported).values())

    @property
    def false_positives(self) -> int:
        return sum((self.reported - self.declared).values())

    @property
    def false_negatives(self) -> int:
        return sum((self.declared - self.reported).values())


def declared_defects(fixture: Path) -> Counter[str]:
    """Rule ids the fixture's author declared, one per table row."""
    intent = fixture / "intent.md"
    if not intent.is_file():
        raise FileNotFoundError(f"{fixture.name} declares no intent.md")
    counted: Counter[str] = Counter()
    for line in intent.read_text().splitlines():
        if not line.startswith("|"):
            continue
        for rule_id in DECLARED.findall(line):
            counted[rule_id] += 1
    return counted


def measure(fixture: Path) -> Measurement:
    result = audit(fixture, generated_at=STAMP)
    return Measurement(
        fixture=fixture.name,
        declared=declared_defects(fixture),
        reported=Counter(finding.rule_id for finding in result.findings),
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    """``None`` rather than 1.0 when the denominator is zero.

    A precision of "1.0" computed over nothing is the most misleading number a
    benchmark can print.
    """
    return numerator / denominator if denominator else None


def run(fixtures: Path = FIXTURES) -> dict[str, Any]:
    names = sorted(
        path.name for path in fixtures.iterdir() if (path / "intent.md").is_file()
    )
    measurements = [measure(fixtures / name) for name in names]

    true_positives = sum(m.true_positives for m in measurements)
    false_positives = sum(m.false_positives for m in measurements)
    false_negatives = sum(m.false_negatives for m in measurements)

    clean = [m for m in measurements if not m.declared]
    clean_false_positives = sum(m.false_positives for m in clean)

    return {
        "measured_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "tool_version": __version__,
        "ruleset_version": RULESET_VERSION,
        "corpus": {
            "kind": "hand-curated synthetic fixtures",
            "repositories": len(measurements),
            "declared_defects": true_positives + false_negatives,
        },
        "sc_001_detection": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": _ratio(true_positives, true_positives + false_positives),
            "recall": _ratio(true_positives, true_positives + false_negatives),
        },
        "sc_002_false_positives_on_clean_repositories": {
            "repositories": len(clean),
            "false_positives": clean_false_positives,
        },
        "per_fixture": [
            {
                "fixture": m.fixture,
                "declared": sum(m.declared.values()),
                "reported": sum(m.reported.values()),
                "true_positives": m.true_positives,
                "false_positives": m.false_positives,
                "false_negatives": m.false_negatives,
            }
            for m in measurements
        ],
        "caveats": [
            "The corpus is hand-curated and synthetic. These figures describe "
            "detection against declared intent on six small repositories, and "
            "say nothing about the long tail of real-world workflows.",
            "The denominator is the defect table in each fixture's intent.md, "
            "written before the rule that detects it.",
            f"Figures are only comparable against ruleset {RULESET_VERSION}.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable output"
    )
    arguments = parser.parse_args()

    report = run()
    if arguments.json:
        print(json.dumps(report, indent=2))
        return 0

    detection = report["sc_001_detection"]
    print(f"ppv {report['tool_version']}  ruleset {report['ruleset_version']}")
    print(
        f"corpus: {report['corpus']['repositories']} fixtures, "
        f"{report['corpus']['declared_defects']} declared defects"
    )
    print("")
    print(f"  true positives : {detection['true_positives']}")
    print(f"  false positives: {detection['false_positives']}")
    print(f"  false negatives: {detection['false_negatives']}")
    print(f"  precision      : {detection['precision']}")
    print(f"  recall         : {detection['recall']}")
    print("")
    clean = report["sc_002_false_positives_on_clean_repositories"]
    print(
        f"  false positives on {clean['repositories']} clean repositor(ies): "
        f"{clean['false_positives']}"
    )
    print("")
    for caveat in report["caveats"]:
        print(f"  - {caveat}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
