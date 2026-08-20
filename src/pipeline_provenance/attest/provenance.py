"""SLSA build provenance as an in-toto statement.

The statement answers one question — where did this artifact come from — and
this module is careful not to imply it answers any other. There is no field in
here that says the artifact is safe, and none that could be read that way.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from pipeline_provenance.model import Subject

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://github.com/tomdgImpact/Pipeline-Provenance/buildtypes/workflow/v1"

#: Read in blocks so a large artifact does not have to fit in memory.
_BLOCK = 1024 * 1024


def digest(path: Path) -> str:
    """SHA-256 of a file, as an artifact is named by content and not by name."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(_BLOCK):
            hasher.update(block)
    return hasher.hexdigest()


def subjects(
    paths: list[Path], *, relative_to: Path | None = None
) -> tuple[Subject, ...]:
    """Name each artifact by path and content digest."""
    if not paths:
        raise ValueError("no subject: an attestation about nothing attests to nothing")
    return tuple(
        Subject(
            name=(path.relative_to(relative_to) if relative_to else path).as_posix(),
            sha256=digest(path),
        )
        for path in sorted(paths)
    )


def statement(
    *,
    subjects: tuple[Subject, ...],
    builder_id: str,
    source_uri: str,
    source_digest: str,
    invocation_id: str,
    started_on: str,
    finished_on: str,
    resolved_dependencies: tuple[dict[str, Any], ...] = (),
    external_parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the in-toto statement.

    ``builder_id`` is the load-bearing field: verification asserts an identity,
    not the possession of a key, so a statement whose builder is vague is a
    statement no policy can be written against.
    """
    if not builder_id:
        raise ValueError(
            "builder_id is required: an attestation with no builder identity "
            "cannot be verified against one"
        )
    return {
        "_type": STATEMENT_TYPE,
        "subject": [subject.to_dict() for subject in subjects],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": external_parameters or {},
                "internalParameters": {},
                "resolvedDependencies": [
                    {
                        "uri": source_uri,
                        "digest": {"gitCommit": source_digest},
                    },
                    *resolved_dependencies,
                ],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": started_on,
                    "finishedOn": finished_on,
                },
            },
        },
    }
