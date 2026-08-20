"""What a build emits. Nothing here is trusted by anyone: these documents are
produced inside the untrusted execution context, and only the admission point
decides what they are worth."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_provenance.attest import provenance, sbom
from pipeline_provenance.model import AttestationSet, Subject

STAMP = "2026-08-20T00:00:00Z"


def _subject(name: str = "app.whl") -> Subject:
    return Subject(name=name, sha256="a" * 64)


def _statement(**overrides: object) -> dict[str, object]:
    kwargs: dict[str, object] = {
        "subjects": (_subject(),),
        "builder_id": "https://github.com/tomdgImpact/Pipeline-Provenance/.github/workflows/hardened-build.yml@refs/tags/v0.1.0",
        "source_uri": "git+https://github.com/tomdgImpact/Pipeline-Provenance",
        "source_digest": "b" * 40,
        "invocation_id": "run-1",
        "started_on": STAMP,
        "finished_on": STAMP,
    }
    kwargs.update(overrides)
    return provenance.statement(**kwargs)  # type: ignore[arg-type]


class TestDigest:
    def test_an_artifact_is_named_by_content(self, tmp_path: Path) -> None:
        path = tmp_path / "app.whl"
        path.write_bytes(b"payload")
        assert provenance.digest(path) == (
            "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
        )

    def test_two_names_for_the_same_bytes_share_a_digest(self, tmp_path: Path) -> None:
        first, second = tmp_path / "a.whl", tmp_path / "b.whl"
        first.write_bytes(b"same")
        second.write_bytes(b"same")
        assert provenance.digest(first) == provenance.digest(second)

    def test_a_large_file_is_hashed_without_loading_it_whole(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "big.bin"
        path.write_bytes(b"x" * (3 * 1024 * 1024 + 7))
        assert len(provenance.digest(path)) == 64


class TestSubjects:
    def test_no_subject_is_refused(self) -> None:
        """An attestation about nothing attests to nothing."""
        with pytest.raises(ValueError, match="attests to nothing"):
            provenance.subjects([])

    def test_names_are_relative_to_the_build_root(self, tmp_path: Path) -> None:
        (tmp_path / "dist").mkdir()
        artifact = tmp_path / "dist" / "app.whl"
        artifact.write_bytes(b"payload")
        (subject,) = provenance.subjects([artifact], relative_to=tmp_path)
        assert subject.name == "dist/app.whl"

    def test_subject_order_is_deterministic(self, tmp_path: Path) -> None:
        for name in ("c.whl", "a.whl", "b.whl"):
            (tmp_path / name).write_bytes(name.encode())
        found = provenance.subjects(
            [tmp_path / "c.whl", tmp_path / "a.whl", tmp_path / "b.whl"],
            relative_to=tmp_path,
        )
        assert [s.name for s in found] == ["a.whl", "b.whl", "c.whl"]


class TestStatement:
    def test_the_envelope_is_in_toto_and_slsa(self) -> None:
        document = _statement()
        assert document["_type"] == provenance.STATEMENT_TYPE
        assert document["predicateType"] == provenance.PREDICATE_TYPE

    def test_a_missing_builder_identity_is_refused(self) -> None:
        """Verification asserts an identity, not the possession of a key. A
        statement with a vague builder is one no policy can be written against."""
        with pytest.raises(ValueError, match="builder identity"):
            _statement(builder_id="")

    def test_the_source_revision_is_recorded_as_a_resolved_dependency(self) -> None:
        document = _statement()
        predicate = document["predicate"]
        assert isinstance(predicate, dict)
        dependencies = predicate["buildDefinition"]["resolvedDependencies"]
        assert dependencies[0]["digest"]["gitCommit"] == "b" * 40

    def test_nothing_in_the_statement_claims_the_artifact_is_correct(self) -> None:
        """Provenance answers origin. Any field a reader could take as a safety
        claim is a field that will eventually be quoted as one."""
        flattened = repr(_statement()).lower()
        for word in ("safe", "secure", "trusted", "verified", "approved"):
            assert word not in flattened


class TestSbom:
    def test_the_envelope_is_cyclonedx(self) -> None:
        document = sbom.document(
            subjects=(_subject(),), serial_number="urn:uuid:1", timestamp=STAMP
        )
        assert document["bomFormat"] == "CycloneDX"
        assert document["specVersion"] == "1.5"

    def test_no_subject_is_refused(self) -> None:
        with pytest.raises(ValueError, match="describes nothing"):
            sbom.document(subjects=(), serial_number="urn:uuid:1", timestamp=STAMP)

    def test_the_coverage_limitation_is_written_into_the_document(self) -> None:
        """A consumer reading the SBOM without reading our source still has to
        learn that no ecosystem-aware resolution was performed."""
        document = sbom.document(
            subjects=(_subject(),), serial_number="urn:uuid:1", timestamp=STAMP
        )
        metadata = document["metadata"]
        assert isinstance(metadata, dict)
        properties = metadata["properties"]
        coverage = next(p for p in properties if p["name"] == sbom.COVERAGE_PROPERTY)
        assert "no ecosystem-aware component resolution" in coverage["value"]

    def test_injected_components_are_carried_through(self) -> None:
        document = sbom.document(
            subjects=(_subject(),),
            serial_number="urn:uuid:1",
            timestamp=STAMP,
            components=({"type": "library", "name": "requests", "version": "2.32.3"},),
        )
        components = document["components"]
        assert isinstance(components, list)
        assert any(c["name"] == "requests" for c in components)


class TestAtomicity:
    def test_provenance_without_an_sbom_is_refused(self) -> None:
        """Half an attestation set is not a weaker guarantee. It is a different
        and useless one."""
        with pytest.raises(ValueError, match="atomic"):
            AttestationSet(subjects=(_subject(),), provenance=_statement(), sbom={})

    def test_an_sbom_without_provenance_is_refused(self) -> None:
        with pytest.raises(ValueError, match="atomic"):
            AttestationSet(
                subjects=(_subject(),),
                provenance={},
                sbom=sbom.document(
                    subjects=(_subject(),), serial_number="urn:uuid:1", timestamp=STAMP
                ),
            )

    def test_a_set_with_no_subject_is_refused(self) -> None:
        with pytest.raises(ValueError, match="attests to nothing"):
            AttestationSet(subjects=(), provenance=_statement(), sbom={"a": 1})

    def test_a_complete_set_is_accepted(self) -> None:
        document = sbom.document(
            subjects=(_subject(),), serial_number="urn:uuid:1", timestamp=STAMP
        )
        attestation = AttestationSet(
            subjects=(_subject(),), provenance=_statement(), sbom=document
        )
        assert attestation.subjects[0].name == "app.whl"
