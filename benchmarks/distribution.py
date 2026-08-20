"""SC-003: how the four invariants hold across public repositories.

Aggregate only. No individual project is named in any output, and none is
contacted — only public workflow files are read. The point of the figure is the
shape of the distribution, not a league table, and naming projects would turn a
measurement into an accusation.

Online by design, and therefore opt-in: ``--online`` is required, and without it
the module refuses rather than emitting a figure derived from nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pipeline_provenance import __version__
from pipeline_provenance.audit import audit
from pipeline_provenance.model import RULESET_VERSION, Invariant, Status

CORPUS = Path(__file__).parent / "corpus.txt"
API = "https://api.github.com"
TIMEOUT = 20
MAX_WORKFLOWS = 25


def _request(url: str) -> Any:
    headers = {
        "accept": "application/vnd.github+json",
        "user-agent": f"pipeline-provenance/{__version__}",
    }
    token = os.environ.get("PPV_GITHUB_TOKEN")
    if token:
        headers["authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - https only
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
        return json.loads(response.read())


def _download(url: str) -> str:
    request = urllib.request.Request(  # noqa: S310 - https only
        url, headers={"user-agent": f"pipeline-provenance/{__version__}"}
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
        body: bytes = response.read()
    return body.decode("utf-8", "replace")


def materialise(repository: str, destination: Path) -> int:
    """Write a repository's workflow files into ``destination``.

    Only ``.github/workflows`` is fetched. Nothing else about the repository is
    read, stored, or reported.
    """
    workflows = destination / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    listing = _request(f"{API}/repos/{repository}/contents/.github/workflows")
    written = 0
    for entry in listing:
        if entry.get("type") != "file":
            continue
        name = str(entry["name"])
        if not name.endswith((".yml", ".yaml")):
            continue
        (workflows / name).write_text(_download(str(entry["download_url"])))
        written += 1
        if written >= MAX_WORKFLOWS:
            break
    return written


def run(repositories: list[str]) -> dict[str, Any]:
    statuses: dict[str, Counter[str]] = {
        invariant.value: Counter() for invariant in Invariant
    }
    findings_by_rule: Counter[str] = Counter()
    repositories_by_rule: Counter[str] = Counter()
    examined = 0
    unreachable = 0
    workflows_total = 0

    for repository in repositories:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            try:
                workflows_total += materialise(repository, root)
            except (urllib.error.URLError, OSError, KeyError, ValueError):
                # Counted, never named. A repository that could not be read is
                # part of the method, not a silent omission from the sample.
                unreachable += 1
                continue
            result = audit(root, generated_at="1970-01-01T00:00:00Z")
            if not result.workflows_examined:
                unreachable += 1
                continue
            examined += 1
            for report in result.invariants:
                statuses[report.invariant.value][report.status.value] += 1
            reported = [finding.rule_id for finding in result.findings]
            findings_by_rule.update(reported)
            # Counted once per repository as well as once per occurrence: "341
            # findings" and "14 repositories affected" answer different
            # questions, and reporting one under the other's name is the kind of
            # slip that makes a whole table untrustworthy.
            repositories_by_rule.update(set(reported))

    return {
        "measured_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "tool_version": __version__,
        "ruleset_version": RULESET_VERSION,
        "sample": {
            "requested": len(repositories),
            "examined": examined,
            "unreachable_or_empty": unreachable,
            "workflow_files": workflows_total,
            "selection": (
                "widely-used open-source projects across several ecosystems, "
                "listed in benchmarks/corpus.txt"
            ),
        },
        "invariants": {
            invariant: {
                status: statuses[invariant][status]
                for status in (Status.PASSING, Status.FAILING, Status.UNVERIFIED)
            }
            for invariant in statuses
        },
        "most_common_findings": [
            {
                "rule_id": rule_id,
                "findings": count,
                "repositories_affected": repositories_by_rule[rule_id],
            }
            for rule_id, count in findings_by_rule.most_common(12)
        ],
        "caveats": [
            "Aggregate only. No individual repository is named, by policy.",
            "The sample is small and deliberately chosen, not random. It "
            "describes these projects and is not a population estimate.",
            "Only .github/workflows was read. Reusable workflows called from "
            "other repositories were not followed.",
            "I4 is assessed by declaration; no runner was observed.",
            f"Comparable only against ruleset {RULESET_VERSION}.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--online",
        action="store_true",
        help="Required. This module reads public repositories over the network.",
    )
    parser.add_argument("--output", type=Path, default=None)
    arguments = parser.parse_args()

    if not arguments.online:
        print(
            "distribution.py reads public repositories over the network and is "
            "opt-in. Re-run with --online. Refusing rather than emitting a "
            "figure derived from nothing.",
            file=sys.stderr,
        )
        return 2

    repositories = [
        line.strip()
        for line in CORPUS.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    report = run(repositories)
    rendered = json.dumps(report, indent=2)
    if arguments.output:
        arguments.output.write_text(rendered + "\n")
        print(f"wrote {arguments.output}", file=sys.stderr)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
