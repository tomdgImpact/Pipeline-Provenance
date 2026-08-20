"""I3 — provenance generated, and actually verified somewhere."""

from __future__ import annotations

from pathlib import Path

from pipeline_provenance.discovery import Repository, load_repository
from pipeline_provenance.model import Assessment, Status
from pipeline_provenance.rules import i3_provenance as i3

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "repos"


def _rules(repository: Repository) -> list[str]:
    return sorted(f.rule_id for f in i3.evaluate(repository).findings)


def _fixture(name: str) -> Repository:
    return load_repository(FIXTURES / name)


def _repo(tmp_path: Path, files: dict[str, str]) -> Repository:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        (directory / name).write_text(body)
    return load_repository(tmp_path)


BUILDS = (
    "name: build\non: push\npermissions: {}\njobs:\n  build:\n    steps:\n"
    "      - run: npm publish\n"
)


class TestNaiveFixture:
    def test_generation_and_verification_are_both_reported(self) -> None:
        assert _rules(_fixture("naive")) == [
            "I3/no-admission-verification",
            "I3/no-provenance",
            "I3/no-sbom",
        ]

    def test_the_verification_finding_is_unverified_not_a_failure(self) -> None:
        """The admission point may legitimately live outside this repository."""
        report = i3.evaluate(_fixture("naive"))
        verification = next(
            f for f in report.findings if f.rule_id == "I3/no-admission-verification"
        )
        assert verification.assessment is Assessment.UNVERIFIED


class TestHardenedFixture:
    def test_no_finding_is_reported(self) -> None:
        assert _rules(_fixture("hardened")) == []

    def test_verification_in_a_second_workflow_counts(self) -> None:
        """The build emits; a separate deploy workflow verifies. Both halves are
        present, which is the whole point of the invariant."""
        assert i3.evaluate(_fixture("hardened")).status is Status.PASSING


class TestNothingToAttest:
    def test_a_repository_that_produces_nothing_reports_no_findings(
        self, tmp_path: Path
    ) -> None:
        repository = _repo(
            tmp_path,
            {
                "ci.yml": "name: ci\non: push\npermissions: {}\njobs:\n  test:\n"
                "    steps:\n      - run: make test\n"
            },
        )
        report = i3.evaluate(repository)
        assert report.findings == ()
        assert report.status is Status.PASSING
        assert "produces a deployable artifact" in (report.note or "")


class TestGenerationMarkers:
    def test_provenance_emitted_by_a_run_command_counts(self, tmp_path: Path) -> None:
        repository = _repo(
            tmp_path,
            {
                "b.yml": BUILDS.replace(
                    "      - run: npm publish\n",
                    "      - run: npm publish\n      - run: cosign attest --yes dist\n",
                )
            },
        )
        assert "I3/no-provenance" not in _rules(repository)

    def test_sbom_emitted_by_syft_counts(self, tmp_path: Path) -> None:
        repository = _repo(
            tmp_path,
            {
                "b.yml": BUILDS.replace(
                    "      - run: npm publish\n",
                    "      - run: npm publish\n"
                    "      - run: syft dir:. -o cyclonedx-json\n",
                )
            },
        )
        assert "I3/no-sbom" not in _rules(repository)

    def test_generation_alone_does_not_satisfy_the_invariant(
        self, tmp_path: Path
    ) -> None:
        """An attestation nobody checks costs build time and stops nothing."""
        repository = _repo(
            tmp_path,
            {
                "b.yml": BUILDS.replace(
                    "      - run: npm publish\n",
                    "      - run: npm publish\n"
                    "      - run: cosign attest --yes dist\n"
                    "      - run: syft dir:. -o cyclonedx-json\n",
                )
            },
        )
        assert _rules(repository) == ["I3/no-admission-verification"]


class TestMonorepoFixture:
    def test_findings_point_at_the_workflow_that_publishes(self) -> None:
        report = i3.evaluate(_fixture("monorepo"))
        assert {f.location.path for f in report.findings} == {
            ".github/workflows/release.yml"
        }


def test_an_unparsable_workflow_leaves_the_invariant_unverified() -> None:
    assert i3.evaluate(_fixture("invalid-yaml")).status is Status.UNVERIFIED
