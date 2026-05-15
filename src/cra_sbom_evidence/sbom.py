"""SBOM parser — CycloneDX and SPDX JSON formats.

Supports:
- CycloneDX 1.4, 1.5, 1.6  (``bomFormat == "CycloneDX"``)
- SPDX 2.3 JSON             (``spdxVersion`` present)

Only the fields relevant to CRA evidence generation are extracted.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class SbomComponent(BaseModel):
    """A single software component within an SBOM."""

    name: str
    version: str | None = None
    purl: str | None = None
    bom_ref: str | None = None
    supplier: str | None = None
    licenses: list[str] = Field(default_factory=list)
    component_type: str | None = None


class SbomVulnerability(BaseModel):
    """A vulnerability record embedded in a CycloneDX SBOM."""

    vuln_id: str
    severity: str | None = None
    score: float | None = None
    affects_refs: list[str] = Field(default_factory=list)
    vex_state: str | None = None       # resolved/exploitable/in_triage/false_positive/not_affected
    vex_justification: str | None = None


class SbomDocument(BaseModel):
    """Normalised view of an SBOM from either CycloneDX or SPDX."""

    format: str                        # "CycloneDX" | "SPDX"
    spec_version: str
    serial_number: str | None = None
    doc_namespace: str | None = None
    created_at: str | None = None
    metadata_component_name: str | None = None
    metadata_component_version: str | None = None
    components: list[SbomComponent] = Field(default_factory=list)
    vulnerabilities: list[SbomVulnerability] = Field(default_factory=list)
    # Top-level hashes from metadata.component (CycloneDX) or document-level (SPDX)
    hashes: dict[str, str] = Field(default_factory=dict)
    # Raw source path for audit purposes
    source_path: str | None = None


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _parse_cyclonedx(data: dict[str, Any], path: str) -> SbomDocument:
    """Parse a CycloneDX JSON dict into a ``SbomDocument``."""
    spec_version: str = str(data.get("specVersion", ""))
    serial: str | None = data.get("serialNumber")

    # Metadata component
    metadata: dict[str, Any] = data.get("metadata", {})
    meta_comp: dict[str, Any] = metadata.get("component", {})
    meta_name: str | None = meta_comp.get("name")
    meta_version: str | None = meta_comp.get("version")
    created_at: str | None = metadata.get("timestamp")

    # Hashes from metadata component
    raw_hashes: list[dict[str, Any]] = meta_comp.get("hashes", [])
    hashes: dict[str, str] = {
        h.get("alg", ""): h.get("content", "")
        for h in raw_hashes
        if isinstance(h, dict)
    }

    # Components
    components: list[SbomComponent] = []
    for raw in data.get("components", []):
        if not isinstance(raw, dict):
            continue
        supplier_info: dict[str, Any] | str | None = raw.get("supplier")
        supplier_name: str | None = None
        if isinstance(supplier_info, dict):
            supplier_name = supplier_info.get("name")
        elif isinstance(supplier_info, str):
            supplier_name = supplier_info

        licenses: list[str] = []
        for lic in raw.get("licenses", []):
            if not isinstance(lic, dict):
                continue
            inner = lic.get("license", {})
            if isinstance(inner, dict):
                lid = inner.get("id") or inner.get("name")
                if lid:
                    licenses.append(str(lid))

        components.append(
            SbomComponent(
                name=str(raw.get("name", "")),
                version=raw.get("version"),
                purl=raw.get("purl"),
                bom_ref=raw.get("bom-ref"),
                supplier=supplier_name,
                licenses=licenses,
                component_type=raw.get("type"),
            )
        )

    # Vulnerabilities (CycloneDX 1.4+ embedded VEX)
    vulnerabilities: list[SbomVulnerability] = []
    for raw in data.get("vulnerabilities", []):
        if not isinstance(raw, dict):
            continue
        ratings: list[dict[str, Any]] = raw.get("ratings", [])
        score: float | None = None
        severity: str | None = None
        if ratings and isinstance(ratings[0], dict):
            score_val = ratings[0].get("score")
            score = float(score_val) if score_val is not None else None
            sev_val = ratings[0].get("severity")
            severity = str(sev_val) if sev_val else None

        affects: list[str] = [
            str(a.get("ref", ""))
            for a in raw.get("affects", [])
            if isinstance(a, dict) and a.get("ref")
        ]
        analysis: dict[str, Any] = raw.get("analysis", {})

        vulnerabilities.append(
            SbomVulnerability(
                vuln_id=str(raw.get("id", "")),
                severity=severity,
                score=score,
                affects_refs=affects,
                vex_state=analysis.get("state"),
                vex_justification=analysis.get("justification"),
            )
        )

    return SbomDocument(
        format="CycloneDX",
        spec_version=spec_version,
        serial_number=serial,
        created_at=created_at,
        metadata_component_name=meta_name,
        metadata_component_version=meta_version,
        components=components,
        vulnerabilities=vulnerabilities,
        hashes=hashes,
        source_path=path,
    )


def _parse_spdx(data: dict[str, Any], path: str) -> SbomDocument:
    """Parse an SPDX 2.3 JSON dict into a ``SbomDocument``."""
    spec_version: str = str(data.get("spdxVersion", ""))
    doc_namespace: str | None = data.get("documentNamespace")
    created_at: str | None = None
    creation_info: dict[str, Any] = data.get("creationInfo", {})
    if isinstance(creation_info, dict):
        created_at = creation_info.get("created")

    components: list[SbomComponent] = []
    for pkg in data.get("packages", []):
        if not isinstance(pkg, dict):
            continue
        # SPDX does not have a standard purl field in 2.3, but some tools add externalRefs
        purl: str | None = None
        for ref in pkg.get("externalRefs", []):
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break

        concluded_license = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
        licenses: list[str] = (
            [concluded_license]
            if concluded_license and concluded_license not in ("NOASSERTION", "NONE")
            else []
        )

        components.append(
            SbomComponent(
                name=str(pkg.get("name", "")),
                version=pkg.get("versionInfo"),
                purl=purl,
                bom_ref=pkg.get("SPDXID"),
                licenses=licenses,
            )
        )

    return SbomDocument(
        format="SPDX",
        spec_version=spec_version,
        doc_namespace=doc_namespace,
        created_at=created_at,
        components=components,
        source_path=path,
    )


def parse_sbom(path: str | Path) -> SbomDocument:
    """Parse a CycloneDX or SPDX JSON SBOM file.

    Detection logic:
    - CycloneDX: ``bomFormat == "CycloneDX"``
    - SPDX: ``spdxVersion`` key present

    Args:
        path: Path to the JSON SBOM file.

    Returns:
        A normalised ``SbomDocument``.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the format is not recognised.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"SBOM file not found: {p}")
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"SBOM must be a JSON object, got: {type(data).__name__}")

    if data.get("bomFormat") == "CycloneDX":
        return _parse_cyclonedx(data, str(p))
    if "spdxVersion" in data:
        return _parse_spdx(data, str(p))
    raise ValueError(
        "Unrecognised SBOM format: expected 'bomFormat'=='CycloneDX' or 'spdxVersion' key. "
        f"Keys found: {list(data.keys())[:10]}"
    )
