"""Instructions in the documentation must work.

A security tool whose install command fails is a security tool nobody runs, and
an instruction that fails silently teaches a reader to distrust the rest of the
document. These assertions caught three broken paths at v0.1.0: two `pipx
install` lines pointing at a package index that has no such package, and a
`make install` target that assumed a virtual environment already existed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

#: The project is not published to any index. Until it is, any instruction that
#: resolves it by name is an instruction that fails.
FROM_INDEX = re.compile(
    r"(pipx install|pip install|uv tool install)\s+"
    r"(--[\w-]+(=\S+)?\s+)*pipeline-provenance(?![./@])"
)


def _copyable_lines(document: Path) -> list[tuple[int, str]]:
    """Lines a reader would copy: fenced code, and YAML `run:` steps.

    Prose that *warns against* a command is not an instruction, and a check
    that cannot tell the two apart flags the warning it asked for.
    """
    lines = document.read_text().splitlines()
    if document.suffix in (".yml", ".yaml"):
        return [(n, ln) for n, ln in enumerate(lines, start=1) if "run:" in ln]

    inside = False
    copyable: list[tuple[int, str]] = []
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("```"):
            inside = not inside
            continue
        if inside:
            copyable.append((number, line))
    return copyable


def _documents(repo_root: Path) -> list[Path]:
    found = [repo_root / "README.md"]
    for directory in ("docs", ".github/actions"):
        found.extend(sorted((repo_root / directory).rglob("*.md")))
        found.extend(sorted((repo_root / directory).rglob("*.yml")))
    return [path for path in found if path.is_file()]


def test_nothing_tells_a_reader_to_install_from_a_package_index(
    repo_root: Path,
) -> None:
    """`pip install pipeline-provenance` resolves to nothing and always has."""
    offenders: list[str] = []
    for document in _documents(repo_root):
        for number, line in _copyable_lines(document):
            if FROM_INDEX.search(line):
                offenders.append(
                    f"{document.relative_to(repo_root)}:{number}: {line.strip()}"
                )
    assert not offenders, (
        "instructions resolving the project from a package index it is not on:\n  "
        + "\n  ".join(offenders)
    )


def test_the_install_guide_states_its_prerequisites(repo_root: Path) -> None:
    """A version requirement discovered by failing is a version requirement
    that was not documented."""
    guide = (repo_root / "docs" / "INSTALL.md").read_text()
    assert "3.12" in guide
    assert "uv" in guide
    assert "cosign" in guide


def test_the_install_guide_says_the_project_is_not_published(
    repo_root: Path,
) -> None:
    guide = (repo_root / "docs" / "INSTALL.md").read_text()
    assert "Not on PyPI" in guide


def test_the_readme_shows_what_the_tool_actually_prints(repo_root: Path) -> None:
    """A security tool that never shows its output asks the reader to imagine
    the deliverable."""
    readme = (repo_root / "README.md").read_text()
    assert "## Quickstart" in readme
    assert "finding(s):" in readme
    assert "fix:" in readme


def test_the_make_install_target_creates_its_own_environment(
    repo_root: Path,
) -> None:
    """It failed on a clean machine because it assumed an active venv."""
    makefile = (repo_root / "Makefile").read_text()
    install = makefile.split("install:")[1].split("\n.PHONY")[0]
    assert "uv venv" in install


def test_the_composite_action_installs_from_its_own_checkout(
    repo_root: Path,
) -> None:
    """Resolving the tool at build time would make the pinned commit and the
    executed code two different things — the invariant this action enforces."""
    action = (
        repo_root / ".github" / "actions" / "policy-gate" / "action.yml"
    ).read_text()
    assert "GITHUB_ACTION_PATH" in action
    assert "pipx install" not in action
