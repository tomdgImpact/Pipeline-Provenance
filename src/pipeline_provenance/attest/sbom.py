"""A CycloneDX bill of materials for the produced artifacts.

**What this generator does and does not do.** It records the artifacts
themselves, named by content digest, and the dependency manifests the build
resolved from. It does **not** perform ecosystem-aware component resolution:
that is what `syft` and its equivalents exist for, and pretending otherwise
would ship an SBOM that looks complete and is not.

The distinction is written into the document itself, as a property on the
metadata, so a consumer reading the SBOM without reading this file still learns
the limitation.
"""

from __future__ import annotations

from typing import Any

from pipeline_provenance import __version__
from pipeline_provenance.model import Subject

BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.5"

COVERAGE_PROPERTY = "pipeline-provenance:coverage"
COVERAGE_VALUE = (
    "subject-artifacts-and-declared-manifests-only; no ecosystem-aware "
    "component resolution was performed by this generator"
)


def document(
    *,
    subjects: tuple[Subject, ...],
    serial_number: str,
    timestamp: str,
    manifests: tuple[str, ...] = (),
    components: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    """Build the CycloneDX document.

    ``components`` is where a real generator's output is injected. When it is
    empty the document says so rather than presenting an empty inventory as a
    clean one.
    """
    if not subjects:
        raise ValueError("an SBOM with no subject describes nothing")

    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "tomdgImpact", "name": "ppv", "version": __version__}],
            "component": {
                "type": "application",
                "bom-ref": subjects[0].name,
                "name": subjects[0].name,
                "hashes": [{"alg": "SHA-256", "content": subjects[0].sha256}],
            },
            "properties": [
                {"name": COVERAGE_PROPERTY, "value": COVERAGE_VALUE},
                *(
                    {"name": "pipeline-provenance:manifest", "value": manifest}
                    for manifest in manifests
                ),
            ],
        },
        "components": [
            *(
                {
                    "type": "file",
                    "bom-ref": subject.name,
                    "name": subject.name,
                    "hashes": [{"alg": "SHA-256", "content": subject.sha256}],
                }
                for subject in subjects[1:]
            ),
            *components,
        ],
    }
