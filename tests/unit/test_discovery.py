"""Discovery does no judging, so these tests assert structure and honesty.

Two properties matter more than the rest: every node knows the line it came
from, and a file that cannot be read is recorded rather than dropped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_provenance.discovery import (
    Repository,
    load_repository,
    load_workflow,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


@pytest.fixture(scope="module")
def naive() -> Repository:
    return load_repository(FIXTURES / "naive")


@pytest.fixture(scope="module")
def hardened() -> Repository:
    return load_repository(FIXTURES / "hardened")


def _write(tmp_path: Path, body: str, name: str = "ci.yml") -> Path:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(body)
    return path


class TestWorkflowStructure:
    def test_jobs_and_steps_are_found(self, naive: Repository) -> None:
        (workflow,) = naive.workflows
        assert [job.name for job in workflow.jobs] == ["build"]
        assert len(workflow.jobs[0].steps) == 5

    def test_triggers_are_read_regardless_of_yaml_version(
        self, naive: Repository
    ) -> None:
        """`on` is a boolean in YAML 1.1 and a string in 1.2. Both are read."""
        (workflow,) = naive.workflows
        assert set(workflow.triggers) == {"push", "pull_request_target"}

    def test_missing_permissions_is_distinguishable_from_empty(
        self, naive: Repository, hardened: Repository
    ) -> None:
        """`permissions: {}` denies everything. A missing block inherits the
        repository default. Conflating them inverts the finding."""
        (naive_workflow,) = naive.workflows
        assert naive_workflow.permissions_declared is False

        build = next(w for w in hardened.workflows if w.path.endswith("build.yml"))
        assert build.permissions_declared is True
        assert build.permissions == {}

    def test_container_and_service_images_are_located(self, naive: Repository) -> None:
        (workflow,) = naive.workflows
        job = workflow.jobs[0]
        assert job.container_image == "python:3.12-slim"
        assert job.container_line is not None

    def test_job_permissions_are_captured_per_job(self, hardened: Repository) -> None:
        build = next(w for w in hardened.workflows if w.path.endswith("build.yml"))
        job = build.jobs[0]
        assert job.permissions_declared is True
        assert job.permissions["contents"] == "read"

    def test_timeout_is_captured(self, hardened: Repository) -> None:
        build = next(w for w in hardened.workflows if w.path.endswith("build.yml"))
        assert build.jobs[0].timeout_minutes == 15


class TestLocationFidelity:
    def test_every_step_carries_a_source_line(self, naive: Repository) -> None:
        (workflow,) = naive.workflows
        for step in workflow.jobs[0].steps:
            assert step.line >= 1

    def test_the_recorded_line_holds_the_reference(self, naive: Repository) -> None:
        """The line must be usable as evidence, not merely present."""
        (workflow,) = naive.workflows
        checkout = next(
            s for s in workflow.jobs[0].steps if s.uses == "actions/checkout@v4"
        )
        assert workflow.source(checkout.line) == "- uses: actions/checkout@v4"

    def test_source_lookup_refuses_an_out_of_range_line(
        self, naive: Repository
    ) -> None:
        (workflow,) = naive.workflows
        assert workflow.source(0) is None
        assert workflow.source(10_000) is None
        assert workflow.source(None) is None


class TestHonestFailure:
    def test_an_unparsable_workflow_is_recorded_not_dropped(self) -> None:
        """A scanner that skips what it cannot read reports green on the
        pipeline most likely to be wrong."""
        repository = load_repository(FIXTURES / "invalid-yaml")
        assert len(repository.workflows) == 1
        assert repository.parsed_workflows == ()
        (broken,) = repository.unparsable_workflows
        assert broken.parse_error
        assert broken.parse_error_line is not None

    def test_a_workflow_that_is_not_a_mapping_is_a_parse_failure(
        self, tmp_path: Path
    ) -> None:
        path = _write(tmp_path, "- just\n- a list\n")
        workflow = load_workflow(path, tmp_path)
        assert workflow.parsed is False
        assert "mapping" in (workflow.parse_error or "")

    def test_a_repository_with_no_workflow_directory_yields_nothing(
        self,
    ) -> None:
        repository = load_repository(FIXTURES / "no-workflows")
        assert repository.workflows == ()

    def test_non_yaml_files_in_the_workflow_directory_are_ignored(
        self, tmp_path: Path
    ) -> None:
        _write(tmp_path, "name: ci\non: push\njobs: {}\n")
        (tmp_path / ".github" / "workflows" / "notes.md").write_text("# notes")
        repository = load_repository(tmp_path)
        assert [w.path for w in repository.workflows] == [".github/workflows/ci.yml"]


class TestArtifactDetection:
    def test_an_upload_step_marks_the_job_as_producing_an_artifact(
        self, naive: Repository
    ) -> None:
        (workflow,) = naive.workflows
        assert workflow.jobs[0].produces_artifact is True

    def test_a_publish_command_marks_the_job_as_producing_an_artifact(
        self, tmp_path: Path
    ) -> None:
        _write(
            tmp_path,
            "name: ci\non: push\njobs:\n  release:\n"
            "    steps:\n      - run: npm publish\n",
        )
        repository = load_repository(tmp_path)
        assert repository.workflows[0].jobs[0].produces_artifact is True

    def test_a_test_only_job_does_not_produce_an_artifact(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "name: ci\non: push\njobs:\n  test:\n    steps:\n      - run: make test\n",
        )
        repository = load_repository(tmp_path)
        assert repository.workflows[0].jobs[0].produces_artifact is False


class TestManifests:
    def test_requirements_without_hashes_is_reported_unhashed(
        self, naive: Repository
    ) -> None:
        (manifest,) = naive.manifests
        assert manifest.path == "requirements.txt"
        assert manifest.hashed is False

    def test_requirements_with_hashes_is_reported_hashed(
        self, hardened: Repository
    ) -> None:
        (manifest,) = hardened.manifests
        assert manifest.hashed is True

    def test_a_lockfile_counts_as_locked(self, tmp_path: Path) -> None:
        _write(tmp_path, "name: ci\non: push\njobs: {}\n")
        (tmp_path / "package-lock.json").write_text("{}")
        repository = load_repository(tmp_path)
        assert repository.manifests == (repository.manifests[0],)
        assert repository.manifests[0].hashed is True


def test_local_composite_actions_are_not_third_party(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "name: ci\non: push\njobs:\n  a:\n    steps:\n"
        "      - uses: ./.github/actions/x\n",
    )
    repository = load_repository(tmp_path)
    step = repository.workflows[0].jobs[0].steps[0]
    assert step.is_third_party is False


class TestDiagnosticSteps:
    """A step that only runs after a failure is debugging output, not a build."""

    def test_a_failure_guarded_upload_does_not_count_as_producing(
        self, tmp_path: Path
    ) -> None:
        _write(
            tmp_path,
            "name: ci\non: push\njobs:\n  test:\n    steps:\n"
            "      - run: make test\n"
            "      - uses: actions/upload-artifact@" + "a" * 40 + "\n"
            "        if: failure()\n"
            "        with:\n          name: logs\n",
        )
        repository = load_repository(tmp_path)
        assert repository.workflows[0].jobs[0].produces_artifact is False

    def test_an_unconditional_upload_still_counts(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "name: ci\non: push\njobs:\n  build:\n    steps:\n"
            "      - uses: actions/upload-artifact@" + "a" * 40 + "\n"
            "        with:\n          name: dist\n",
        )
        repository = load_repository(tmp_path)
        assert repository.workflows[0].jobs[0].produces_artifact is True

    def test_a_cancelled_guard_is_also_diagnostic(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "name: ci\non: push\njobs:\n  build:\n    steps:\n"
            "      - uses: actions/upload-artifact@" + "a" * 40 + "\n"
            "        if: cancelled()\n",
        )
        repository = load_repository(tmp_path)
        assert repository.workflows[0].jobs[0].produces_artifact is False

    def test_an_always_guard_is_not_treated_as_diagnostic(self, tmp_path: Path) -> None:
        """`always()` runs on success too, so it can carry a real deliverable."""
        _write(
            tmp_path,
            "name: ci\non: push\njobs:\n  build:\n    steps:\n"
            "      - uses: actions/upload-artifact@" + "a" * 40 + "\n"
            "        if: always()\n",
        )
        repository = load_repository(tmp_path)
        assert repository.workflows[0].jobs[0].produces_artifact is True
