"""I1 applies to the documentation, not only to the pipeline.

The project's first invariant is that nothing runs unpinned. Until this test
existed, `docs/MIGRATION.md` and the usage comment in
`.github/workflows/hardened-build.yml` told adopters to reference this project
at `@v0.1.0` — a mutable pointer, and precisely the thing the invariant exists
to refuse. A copyable example is an instruction, and an instruction that
contradicts the invariant costs the invariant its credibility.

`test_self_conformance.py` enforces pinning on the workflows this repository
runs. This file enforces the same rule on the workflows this repository tells
other people to write.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

#: A `uses:` value, wherever it appears in a copyable example.
USES = re.compile(r"\buses:\s*(?P<reference>\S+)")

#: The only immutable form: `owner/repo@<40 hex>` or `owner/repo/path@<40 hex>`.
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")

#: A reference into the reader's own checkout resolves to the commit they are
#: already running. There is nothing to pin.
LOCAL = re.compile(r"^(\./|docker://)")

#: `docs/INSTALL.md` shows the shape rather than a specific release, so its
#: reference is a blank the reader fills in. The blank must still name a
#: digest: `@<commit-sha>` teaches the rule, `@<version>` teaches the defect.
SHA_PLACEHOLDER = re.compile(r"@<[\w-]*(sha|digest|commit)[\w-]*>$", re.IGNORECASE)


def _fenced_lines(document: Path) -> list[tuple[int, str]]:
    """Lines inside a markdown code fence — the lines a reader copies.

    Prose that *discusses* tags is not an instruction to use one.
    `docs/adr/0001-pin-by-digest-not-tag.md` argues against `actions/checkout`
    at `@v4` by naming it, and a check that cannot tell an argument from an
    example fails on the document that agrees with it most.
    """
    inside = False
    fenced: list[tuple[int, str]] = []
    for number, line in enumerate(document.read_text().splitlines(), start=1):
        if line.lstrip().startswith("```"):
            inside = not inside
            continue
        if inside:
            fenced.append((number, line))
    return fenced


def _commented_lines(document: Path) -> list[tuple[int, str]]:
    """Lines inside a YAML comment block.

    A workflow's executable steps are already covered by
    `test_self_conformance.py`. What is uncovered there is the usage example in
    a leading comment block, which is documentation that happens to live in a
    `.yml` file.
    """
    return [
        (number, line)
        for number, line in enumerate(document.read_text().splitlines(), start=1)
        if line.lstrip().startswith("#")
    ]


def _documents(repo_root: Path) -> list[Path]:
    found = [repo_root / "README.md"]
    for directory in ("docs", ".github"):
        root = repo_root / directory
        if not root.is_dir():
            continue
        for pattern in ("*.md", "*.yml", "*.yaml"):
            found.extend(sorted(root.rglob(pattern)))
    return [path for path in found if path.is_file()]


def _documented_examples(repo_root: Path) -> list[tuple[Path, int, str, str]]:
    """Every `uses:` reference a reader could copy out of the documentation.

    Yields `(document, line number, stripped line, reference)`.
    """
    examples: list[tuple[Path, int, str, str]] = []
    for document in _documents(repo_root):
        if document.suffix in (".yml", ".yaml"):
            lines = _commented_lines(document)
        else:
            lines = _fenced_lines(document)
        for number, line in lines:
            match = USES.search(line)
            if match:
                examples.append(
                    (document, number, line.strip(), match.group("reference"))
                )
    return examples


def test_the_scan_finds_the_examples_it_is_meant_to_guard(repo_root: Path) -> None:
    """Guard against passing because the scan matched nothing.

    A fence parser that silently stops recognising fences turns this whole file
    green, which is the failure mode worth spending a test on.
    """
    examples = _documented_examples(repo_root)
    suffixes = {document.suffix for document, _n, _line, _reference in examples}
    assert len(examples) >= 5, (
        f"only {len(examples)} documented `uses:` example(s) found; "
        "the scan is no longer reaching the documentation"
    )
    assert ".md" in suffixes, "no markdown example found"
    assert ".yml" in suffixes, "no YAML comment example found"


def test_no_documented_example_references_a_repository_by_tag(
    repo_root: Path,
) -> None:
    """I1 — nothing runs unpinned, including what we tell adopters to run.

    A tag or a branch is a name the publisher may repoint at any time. Telling
    a reader to copy one hands them the mutable pointer this project exists to
    remove, and it does so in the document they trust most.
    """
    offenders = [
        f"{document.relative_to(repo_root)}:{number}: {line}"
        for document, number, line, reference in _documented_examples(repo_root)
        if not LOCAL.match(reference)
        and not PINNED.match(reference)
        and not SHA_PLACEHOLDER.search(reference)
    ]
    assert not offenders, (
        "documented example referencing a repository by a mutable ref rather "
        "than a 40-character commit SHA:\n  " + "\n  ".join(offenders)
    )


def test_every_documented_pin_carries_its_version_comment(repo_root: Path) -> None:
    """A digest with no version beside it is unreadable, and an unreadable
    example is one a reader replaces with the tag they can read.

    This is the convention `test_self_conformance.py` enforces on the workflows
    this repository runs. An example that omits it teaches the reader to omit
    it too.
    """
    missing = [
        f"{document.relative_to(repo_root)}:{number}: {line}"
        for document, number, line, reference in _documented_examples(repo_root)
        if not LOCAL.match(reference) and "#" not in line.rsplit("@", 1)[-1]
    ]
    assert not missing, (
        "documented pin without a trailing version comment:\n  " + "\n  ".join(missing)
    )


def _references_in(document: Path) -> list[str]:
    return [
        match.group("reference")
        for _number, line in _fenced_lines(document)
        if (match := USES.search(line))
    ]


def test_prose_that_argues_against_tags_is_not_read_as_an_instruction(
    tmp_path: Path,
) -> None:
    """The check must fire on copyable examples and nothing else.

    The closely related `test_documented_instructions.py` had to be made
    fence-aware for exactly this reason: a warning naming the bad command was
    being flagged as the bad command.
    """
    pinned = "actions/checkout@" + "f" * 40
    document = tmp_path / "adr.md"
    document.write_text(
        "A tag is a mutable pointer. Never write `uses: actions/checkout@v4`.\n"
        "\n"
        "```yaml\n"
        f"- uses: {pinned} # v5\n"
        "```\n"
        "\n"
        "Writing `uses: owner/repo@main` is the same mistake with a branch.\n"
    )
    assert _references_in(document) == [pinned]


def test_the_check_still_fires_on_a_mutable_ref_inside_a_fence(
    tmp_path: Path,
) -> None:
    """The companion to the previous test: fence-awareness must not become a
    way to miss the defect it was written to catch."""
    document = tmp_path / "guide.md"
    document.write_text(
        "```yaml\n"
        "- uses: tomdgImpact/Pipeline-Provenance/.github/actions/gate@v0.1.0\n"
        "- uses: owner/repo@main\n"
        "```\n"
    )
    references = _references_in(document)
    assert len(references) == 2
    assert not any(PINNED.match(reference) for reference in references)
    assert not any(SHA_PLACEHOLDER.search(reference) for reference in references)
