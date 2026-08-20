"""I1 — nothing runs unpinned."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_provenance.discovery import Repository, load_repository
from pipeline_provenance.model import Assessment, Status
from pipeline_provenance.rules import i1_pinning
from pipeline_provenance.rules.base import (
    has_version_comment,
    is_pinned_action,
    split_action,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def _rules(repository: Repository) -> list[str]:
    return sorted(f.rule_id for f in i1_pinning.evaluate(repository).findings)


def _fixture(name: str) -> Repository:
    return load_repository(FIXTURES / name)


def _repo(tmp_path: Path, body: str, name: str = "ci.yml") -> Repository:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(body)
    return load_repository(tmp_path)


class TestReferenceParsing:
    @pytest.mark.parametrize(
        ("uses", "pinned"),
        [
            ("actions/checkout@" + "a" * 40, True),
            ("actions/checkout@v4", False),
            ("actions/checkout@main", False),
            ("actions/checkout", False),
            ("actions/checkout@" + "A" * 40, False),
            ("actions/checkout@" + "a" * 39, False),
            ("github/codeql-action/upload-sarif@" + "b" * 40, True),
        ],
    )
    def test_only_a_full_commit_sha_counts_as_pinned(
        self, uses: str, pinned: bool
    ) -> None:
        assert is_pinned_action(uses) is pinned

    def test_a_short_sha_is_not_a_pin(self) -> None:
        """Short SHAs collide and can be made to collide deliberately."""
        assert is_pinned_action("actions/checkout@08c6903") is False

    def test_docker_references_are_split_without_a_ref(self) -> None:
        assert split_action("docker://alpine:3.20") == ("docker://alpine:3.20", None)

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("- uses: actions/checkout@" + "a" * 40 + " # v5", True),
            ("- uses: actions/checkout@" + "a" * 40, False),
            ("# uses: actions/checkout@" + "a" * 40, False),
        ],
    )
    def test_version_comment_detection(self, line: str, expected: bool) -> None:
        assert has_version_comment(line) is expected


class TestNaiveFixture:
    def test_every_planted_defect_is_reported(self) -> None:
        assert _rules(_fixture("naive")) == [
            "I1/unhashed-dependencies",
            "I1/unpinned-action",
            "I1/unpinned-action",
            "I1/unpinned-action",
            "I1/unpinned-image",
        ]

    def test_the_invariant_fails(self) -> None:
        assert i1_pinning.evaluate(_fixture("naive")).status is Status.FAILING

    def test_findings_carry_the_line_that_holds_the_reference(self) -> None:
        report = i1_pinning.evaluate(_fixture("naive"))
        unpinned = [f for f in report.findings if f.rule_id == "I1/unpinned-action"]
        for finding in unpinned:
            assert finding.location.line is not None
            assert finding.evidence is not None
            assert "uses:" in finding.evidence


class TestHardenedFixture:
    def test_no_finding_is_reported(self) -> None:
        """The false-positive control. Any finding here is a tool defect."""
        assert _rules(_fixture("hardened")) == []

    def test_the_invariant_passes(self) -> None:
        assert i1_pinning.evaluate(_fixture("hardened")).status is Status.PASSING


class TestPartialFixture:
    def test_a_pin_without_a_version_comment_is_reported_at_low_severity(self) -> None:
        report = i1_pinning.evaluate(_fixture("partial"))
        assert [f.rule_id for f in report.findings] == ["I1/missing-version-comment"]

    def test_hashed_requirements_are_not_reported(self) -> None:
        assert "I1/unhashed-dependencies" not in _rules(_fixture("partial"))


class TestDependencyManifests:
    def test_a_lockfile_suppresses_the_unhashed_finding(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests\n")
        (tmp_path / "uv.lock").write_text("")
        repository = _repo(tmp_path, "name: ci\non: push\njobs: {}\n")
        assert "I1/unhashed-dependencies" not in _rules(repository)

    def test_requirements_without_hashes_is_reported(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests\n")
        repository = _repo(tmp_path, "name: ci\non: push\njobs: {}\n")
        assert "I1/unhashed-dependencies" in _rules(repository)


class TestUnparsableWorkflow:
    def test_the_invariant_is_unverified_not_failing(self) -> None:
        """A file nobody can read supports no verdict in either direction."""
        report = i1_pinning.evaluate(_fixture("invalid-yaml"))
        assert report.status is Status.UNVERIFIED
        assert [f.rule_id for f in report.findings] == ["I1/unparsable-workflow"]
        assert report.findings[0].assessment is Assessment.UNVERIFIED


class TestLocalActions:
    def test_a_local_composite_action_needs_no_pin(self, tmp_path: Path) -> None:
        """`./` resolves inside the repository at the reviewed revision."""
        repository = _repo(
            tmp_path,
            "name: ci\non: push\njobs:\n  a:\n    steps:\n"
            "      - uses: ./.github/actions/build\n",
        )
        assert _rules(repository) == []


class TestServiceImages:
    def test_an_unpinned_service_image_is_reported(self, tmp_path: Path) -> None:
        repository = _repo(
            tmp_path,
            "name: ci\non: push\njobs:\n  a:\n"
            "    services:\n      db:\n        image: postgres:16\n"
            "    steps:\n      - run: make test\n",
        )
        assert _rules(repository) == ["I1/unpinned-image"]

    def test_a_digest_pinned_image_is_not_reported(self, tmp_path: Path) -> None:
        digest = "sha256:" + "c" * 64
        repository = _repo(
            tmp_path,
            "name: ci\non: push\njobs:\n  a:\n"
            f"    container:\n      image: postgres@{digest}\n"
            "    steps:\n      - run: make test\n",
        )
        assert _rules(repository) == []
