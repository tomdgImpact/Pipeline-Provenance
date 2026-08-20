"""SC-008: how long an audit takes, offline, on this machine.

Wall-clock on one laptop is not a portable number, so the report records the
machine it ran on. A timing without its hardware is a timing nobody can
reproduce or contradict.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pipeline_provenance import __version__
from pipeline_provenance.audit import audit
from pipeline_provenance.model import RULESET_VERSION

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "repos"
REPEATS = 20
STAMP = "2026-08-20T00:00:00Z"


def time_audit(target: Path, repeats: int = REPEATS) -> dict[str, Any]:
    samples: list[float] = []
    for _ in range(repeats):
        started = time.perf_counter()
        result = audit(target, generated_at=STAMP)
        samples.append(time.perf_counter() - started)
    return {
        "target": target.name,
        "workflows": len(result.workflows_examined),
        "findings": len(result.findings),
        "repeats": repeats,
        "median_ms": round(statistics.median(samples) * 1000, 2),
        "p95_ms": round(sorted(samples)[int(len(samples) * 0.95) - 1] * 1000, 2),
        "max_ms": round(max(samples) * 1000, 2),
    }


def run() -> dict[str, Any]:
    targets = [
        *(path for path in sorted(FIXTURES.iterdir()) if path.is_dir()),
        REPO_ROOT,
    ]
    return {
        "measured_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "tool_version": __version__,
        "ruleset_version": RULESET_VERSION,
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "processor": platform.processor() or platform.machine(),
        },
        "measurements": [time_audit(target) for target in targets],
        "caveats": [
            "Wall clock on one developer machine, stated above. Not a portable "
            "figure and not a claim about any other hardware.",
            "Offline: no network call is made, so no network variance is "
            "included and none is being hidden either.",
            "The largest target here is this repository. A monorepo with "
            "hundreds of workflows was not measured.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()

    report = run()
    if arguments.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"ppv {report['tool_version']}  ruleset {report['ruleset_version']}")
    print(f"machine: {report['machine']['platform']}")
    print("")
    print(f"{'target':16} {'workflows':>9} {'findings':>8} {'median':>9} {'p95':>9}")
    for row in report["measurements"]:
        print(
            f"{row['target'][:16]:16} {row['workflows']:>9} {row['findings']:>8} "
            f"{row['median_ms']:>7.2f}ms {row['p95_ms']:>7.2f}ms"
        )
    print("")
    for caveat in report["caveats"]:
        print(f"  - {caveat}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
