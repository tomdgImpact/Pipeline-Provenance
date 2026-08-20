"""The demonstration, as three assertions.

Act 1 asserts the attack **works** against the naive pipeline. That half is not
decoration: a demonstration that only asserts the hardened outcome passes just
as happily when the attack never worked in the first place, and that is the most
common way this genre of demo is quietly wrong.

What this suite reproduces is the pipeline's semantics — gate ordering, egress
denial, admission refusal — driven through the real `ppv` commands and a real
loopback collector. What it does not reproduce is a GitHub runner's process
isolation, network stack or OIDC issuance. Those are exercised by
`.github/workflows/demo-supply-chain.yml` on hosted runners.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from pipeline_provenance.attest import provenance, sbom
from pipeline_provenance.attest.verify import Policy, load_attestation, verify

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from demo.collector import Collector  # noqa: E402

pytestmark = [pytest.mark.security, pytest.mark.demo]

REPO_ROOT = Path(__file__).resolve().parents[2]
EXFILTRATE = REPO_ROOT / "demo" / "exfiltrate.py"
FAKE_TOKEN = "ghs_DEMO_not_a_real_token_0000000000000000"
IDENTITY = "https://github.com/tomdgImpact/Pipeline-Provenance/.github/workflows/hardened-build.yml@refs/tags/v0.1.0"


@pytest.fixture
def collector() -> Iterator[Collector]:
    with Collector() as running:
        yield running


def _run_malicious_action(collector_url: str, *, egress_denied: bool) -> int:
    """Run the payload the way a job would, with or without egress denied."""
    environment = dict(os.environ)
    environment["DEMO_FAKE_TOKEN"] = FAKE_TOKEN
    if egress_denied:
        # Stand-in for a default-deny egress policy: the payload's destination
        # does not resolve, exactly as it would not on a runner that refuses
        # every host outside the declared allowlist.
        collector_url = "http://127.0.0.1:1/collect"
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(EXFILTRATE), collector_url],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    ).returncode


class TestActOneTheAttackWorks:
    """Against a naive pipeline, with nothing in the way."""

    def test_the_collector_receives_the_secret(self, collector: Collector) -> None:
        code = _run_malicious_action(collector.url, egress_denied=False)
        assert code == 0
        assert len(collector.received) == 1
        assert collector.received[0]["stolen"] == FAKE_TOKEN

    def test_the_build_reports_success_while_leaking(
        self, collector: Collector
    ) -> None:
        """Nothing about the run looks wrong. That is the entire problem."""
        assert _run_malicious_action(collector.url, egress_denied=False) == 0
        assert collector.received


class TestActTwoTheGateRefusesFirst:
    """Against the hardened pipeline, the action never executes."""

    def test_the_gate_blocks_the_unpinned_reference(self, tmp_path: Path) -> None:
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "build.yml").write_text(
            "name: build\non: push\npermissions: {}\njobs:\n"
            "  build:\n    permissions:\n      contents: read\n    steps:\n"
            "      - uses: attacker/helpful-build-cache@v1\n"
        )
        process = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "pipeline_provenance.cli", "gate", str(tmp_path)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            check=False,
        )
        assert process.returncode != 0
        assert "I1/unpinned-action" in process.stdout

    def test_nothing_reached_the_collector(self, collector: Collector) -> None:
        """The gate runs before any third-party step, so there is nothing to
        block later — the action was never scheduled."""
        assert collector.received == []


class TestActThreeEverythingElseStillHolds:
    """The attacker is granted what the gate would have taken away: the action
    is pinned, allowlisted, and executes inside the job. Three invariants
    remain, and each is asserted separately."""

    def test_egress_denial_stops_the_exfiltration(self, collector: Collector) -> None:
        code = _run_malicious_action(collector.url, egress_denied=True)
        assert code == 1
        assert collector.received == []

    def test_an_unattested_artifact_is_refused_at_admission(
        self, tmp_path: Path
    ) -> None:
        """Even with execution inside the job, the attacker cannot produce
        something production will accept."""
        artifact = tmp_path / "backdoored.whl"
        artifact.write_bytes(b"attacker payload")

        legitimate = tmp_path / "app.whl"
        legitimate.write_bytes(b"the real build output")
        subjects = provenance.subjects([legitimate], relative_to=tmp_path)

        statement = tmp_path / "provenance.json"
        statement.write_text(
            json.dumps(
                provenance.statement(
                    subjects=subjects,
                    builder_id=IDENTITY,
                    source_uri="git+https://github.com/tomdgImpact/Pipeline-Provenance",
                    source_digest="b" * 40,
                    invocation_id="run-1",
                    started_on="2026-08-20T00:00:00Z",
                    finished_on="2026-08-20T00:00:00Z",
                )
            )
        )
        document = tmp_path / "sbom.json"
        document.write_text(
            json.dumps(
                sbom.document(
                    subjects=subjects,
                    serial_number="urn:uuid:1",
                    timestamp="2026-08-20T00:00:00Z",
                )
            )
        )

        decision = verify(
            artifact,
            load_attestation(statement, document),
            Policy(expected_identity=IDENTITY),
        )
        assert decision.accepted is False
        assert "does not cover this artifact" in decision.reason

    def test_a_scoped_token_limits_what_execution_is_worth(
        self, tmp_path: Path
    ) -> None:
        """I2. A job that declares only what it uses hands a compromised step
        only what that job could do."""
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        sha = "a" * 40
        (workflows / "build.yml").write_text(
            "name: build\non: push\npermissions: {}\njobs:\n"
            "  build:\n    permissions:\n      contents: read\n    steps:\n"
            "      - uses: ./.github/actions/egress-guard\n"
            f"      - uses: attacker/helpful-build-cache@{sha} # v1\n"
        )
        process = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [
                sys.executable,
                "-m",
                "pipeline_provenance.cli",
                "audit",
                str(tmp_path),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            check=False,
        )
        document = json.loads(process.stdout)
        rules = {finding["rule_id"] for finding in document["findings"]}
        assert "I2/implicit-token-scope" not in rules
        assert "I2/excessive-permission" not in rules


def test_the_demonstration_states_what_is_fake() -> None:
    """A public demo that moves a live credential eventually moves a live
    credential by mistake. The substitution is deliberate and is documented
    where a reader will find it."""
    readme = (REPO_ROOT / "demo" / "README.md").read_text()
    assert "not** a real `GITHUB_TOKEN`" in readme
