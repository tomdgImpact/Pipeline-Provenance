"""No job may both hold the signing identity and run code the caller wrote.

SLSA v1.2 Build L3 states that "secret material used for authenticating the
provenance ... MUST NOT be accessible to the environment running the
user-defined build steps". On GitHub, `id-token: write` puts
`ACTIONS_ID_TOKEN_REQUEST_TOKEN` into the environment of **every** step of the
job that holds it. A job that also runs caller-supplied code therefore lets
that code request the token and mint an attestation under this workflow's
identity: a valid signature over an artifact nobody here built. That is row
**T-13** of `docs/THREAT_MODEL.md`, and `hardened-build.yml` shipped it —
`${{ inputs.build-command }}` ran in the same job that attested.

The fix was structural, so the test is too: this file asserts the shape rather
than warning about it, across every workflow the repository ships. It is the
regression test for a defect that existed, not a hypothetical.

**What this file does not assert.** Three limits, stated so the pass is not
read as covering them:

- A caller-supplied value reaching a *digest-pinned third-party* action's
  `with:` block is not flagged. Whether that reaches a shell depends on the
  action, which this test cannot see. Only local actions — ours, which do
  shell out — are checked there.
- `runs-on: ${{ inputs.runs-on }}` is not flagged. A caller pointing a signing
  job at a runner they control is a real exposure, but it is a different one:
  T-11, documented and explicitly **not enforced**, and recorded as such in
  `docs/COMPLIANCE_MAPPING.md` §3.1.
- Nothing here observes a runner. The property is static, and static is all it
  claims to be.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

pytestmark = pytest.mark.security

_YAML = YAML(typ="safe", pure=True)

#: Scopes that mint or spend the signing identity. Neither can write to the
#: repository, which is why `test_self_conformance` exempts them from its
#: write-scope rule — but both put signing material within reach of the job.
SIGNING_SCOPES = frozenset({"id-token", "attestations"})

#: A value the caller of the workflow chose: `workflow_call` inputs, and the
#: `workflow_dispatch` form of the same thing.
CALLER_INPUT = re.compile(r"\$\{\{[^}]*?\b(?:inputs|github\.event\.inputs)\.")


def _load(path: Path) -> dict[str, Any]:
    return dict(_YAML.load(path.read_text()))


def _jobs(document: dict[str, Any]) -> dict[str, Any]:
    jobs = document.get("jobs") or {}
    assert isinstance(jobs, dict)
    return jobs


def signing_scopes_held_by(job: dict[str, Any]) -> set[str]:
    """The signing scopes this job grants itself."""
    permissions = job.get("permissions") or {}
    if not isinstance(permissions, dict):
        # `permissions: write-all` — every scope, including both of these.
        return set(SIGNING_SCOPES) if permissions == "write-all" else set()
    return {
        scope
        for scope, level in permissions.items()
        if level == "write" and scope in SIGNING_SCOPES
    }


def caller_input_reaches_execution_at(job: dict[str, Any]) -> list[str]:
    """Every position in ``job`` where a caller-supplied input reaches a shell.

    `run:` is direct. `env:` is one hop: a caller who sets `PATH`, `BASH_ENV`
    or `LD_PRELOAD` is choosing what a later step executes, so an environment
    the caller writes is an environment the caller runs code in. `with:` on a
    local action is one hop the other way — those actions are ours, and they
    interpolate their inputs into `run:` blocks.
    """
    positions: list[str] = []

    for name, value in (job.get("env") or {}).items():
        if CALLER_INPUT.search(str(value)):
            positions.append(f"job-level env.{name}")

    for index, step in enumerate(job.get("steps") or []):
        label = step.get("name") or step.get("uses") or f"step {index}"
        if CALLER_INPUT.search(str(step.get("run") or "")):
            positions.append(f"{label!r} run:")
        for name, value in (step.get("env") or {}).items():
            if CALLER_INPUT.search(str(value)):
                positions.append(f"{label!r} env.{name}")
        if str(step.get("uses") or "").startswith("./"):
            for name, value in (step.get("with") or {}).items():
                if CALLER_INPUT.search(str(value)):
                    positions.append(f"{label!r} with.{name} (local action)")

    return positions


def test_the_repository_ships_a_job_that_signs(workflow_files: list[Path]) -> None:
    """Guard against the assertion below passing because nothing signs.

    A workflow set with no signing scope anywhere satisfies "no job both signs
    and runs caller code" trivially, and would keep satisfying it while the
    control it stands for quietly disappeared.
    """
    signing = [
        f"{path.name}:{name}"
        for path in workflow_files
        for name, job in _jobs(_load(path)).items()
        if signing_scopes_held_by(job)
    ]
    assert signing, "no job holds a signing scope; this suite would pass vacuously"


def test_no_job_both_grants_a_signing_scope_and_runs_a_caller_supplied_input(
    workflow_files: list[Path],
) -> None:
    """The property the build/attest split exists to establish (SLSA L3,
    *Provenance is Unforgeable*; threat model T-13)."""
    offenders: list[str] = []
    for path in workflow_files:
        for name, job in _jobs(_load(path)).items():
            scopes = signing_scopes_held_by(job)
            if not scopes:
                continue
            offenders += [
                f"{path.name}:{name} holds {sorted(scopes)} and executes "
                f"a caller input at {position}"
                for position in caller_input_reaches_execution_at(job)
            ]
    assert not offenders, (
        "the signing identity is reachable from caller-supplied code:\n  "
        + "\n  ".join(offenders)
    )


def test_the_job_running_the_caller_build_command_holds_no_write_scope(
    repo_root: Path,
) -> None:
    """The other half of the same property, asserted positively.

    Separating the jobs is only a fix if the one running the caller's command
    ends up with nothing. A `build` job that kept some unrelated write scope
    would pass the test above and still hand the caller something.
    """
    jobs = _jobs(_load(repo_root / ".github" / "workflows" / "hardened-build.yml"))
    build = jobs["build"]
    assert caller_input_reaches_execution_at(build), (
        "the build job no longer runs a caller-supplied input; if the input "
        "was removed, delete this test rather than letting it assert nothing"
    )
    granted = {
        scope
        for scope, level in (build.get("permissions") or {}).items()
        if level == "write"
    }
    assert granted == set(), f"the caller's build command runs with {sorted(granted)}"


class TestTheDetectorFires:
    """The assertions above are worth exactly what their detector is worth.

    Each case below is the defect in a shape a plausible future edit would
    reintroduce it in. If a case stops being detected, the suite above is
    reporting green on a workflow it can no longer read.
    """

    @staticmethod
    def _job(steps: str, env: str = "") -> dict[str, Any]:
        return dict(
            _YAML.load(
                "permissions:\n"
                "  contents: read\n"
                "  id-token: write\n"
                "  attestations: write\n"
                f"{env}"
                "steps:\n"
                f"{steps}"
            )
        )

    def test_against_the_arrangement_that_actually_shipped(self) -> None:
        """`hardened-build.yml` before the split: one job, caller command,
        signing scope, attestation."""
        job = self._job(
            "  - name: Build\n"
            "    run: ${{ inputs.build-command }}\n"
            "  - uses: actions/attest-build-provenance@e8998f94 # v2\n"
            "    with:\n"
            "      subject-path: dist/*\n"
        )
        assert signing_scopes_held_by(job) == {"id-token", "attestations"}
        positions = caller_input_reaches_execution_at(job)
        assert positions == ["'Build' run:"], positions

    def test_against_a_caller_input_arriving_through_the_environment(self) -> None:
        job = self._job(
            "  - name: Attest\n    run: attest dist/*\n",
            env="env:\n  PATH: ${{ inputs.tool-path }}:/usr/bin\n",
        )
        assert caller_input_reaches_execution_at(job) == ["job-level env.PATH"]

    def test_against_a_caller_input_arriving_through_a_step_environment(self) -> None:
        job = self._job(
            "  - name: Attest\n"
            "    run: attest dist/*\n"
            "    env:\n"
            "      BASH_ENV: ${{ inputs.artifact-path }}\n"
        )
        assert caller_input_reaches_execution_at(job) == ["'Attest' env.BASH_ENV"]

    def test_against_a_caller_input_arriving_through_a_local_action(self) -> None:
        """Our composite actions interpolate their inputs into `run:` blocks,
        so a caller value handed to one is a caller value in a shell."""
        job = self._job(
            "  - uses: ./.github/actions/egress-guard\n"
            "    with:\n"
            "      allowed-endpoints: ${{ inputs.allowed-endpoints }}\n"
        )
        assert caller_input_reaches_execution_at(job) == [
            "'./.github/actions/egress-guard' with.allowed-endpoints (local action)"
        ]

    def test_against_a_dispatch_input(self) -> None:
        job = self._job(
            "  - name: Build\n    run: ${{ github.event.inputs.command }}\n"
        )
        assert caller_input_reaches_execution_at(job) == ["'Build' run:"]

    def test_against_write_all(self) -> None:
        """`permissions: write-all` grants both signing scopes without naming
        either, and a detector reading a mapping would see neither."""
        job = dict(_YAML.load("permissions: write-all\nsteps: []\n"))
        assert signing_scopes_held_by(job) == set(SIGNING_SCOPES)

    def test_it_does_not_fire_on_a_job_that_holds_no_signing_scope(self) -> None:
        """The build job's shape. Running a caller input is the point there;
        flagging it would make the suite unpassable and get it deleted."""
        job = dict(
            _YAML.load(
                "permissions:\n"
                "  contents: read\n"
                "steps:\n"
                "  - name: Build\n"
                "    run: ${{ inputs.build-command }}\n"
            )
        )
        assert signing_scopes_held_by(job) == set()

    def test_it_does_not_fire_on_a_fixed_step(self) -> None:
        """No interpolation, no finding — otherwise the detector is a match on
        the word `run` and proves nothing."""
        job = self._job("  - name: Attest\n    run: attest dist/*\n")
        assert caller_input_reaches_execution_at(job) == []
