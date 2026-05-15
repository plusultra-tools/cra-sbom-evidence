"""Evidence builder.

Joins SBOM + VEX + Product manifest into a structured ``Evidence`` object,
tagging each (CVE × component) pair with the relevant CRA clause and
generating an Art. 14 notification draft when high-severity affected
components are present.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cra_sbom_evidence import __version__
from cra_sbom_evidence.cra_text import get_clause, load_registry
from cra_sbom_evidence.product import ProductManifest
from cra_sbom_evidence.sbom import SbomDocument, SbomVulnerability
from cra_sbom_evidence.vex import VexStatement, VexStatus

# Severity thresholds that trigger Art. 14 draft notifications
_HIGH_SEVERITY_LABELS = {"critical", "high"}
_ART14_TRIGGER_STATUSES: set[VexStatus] = {"affected"}
_ART14_SCORE_THRESHOLD = 7.0


class FindingCraMapping(BaseModel):
    """A single CVE × component finding with CRA clause cross-references."""

    vulnerability_id: str
    component_name: str | None = None
    component_purl: str | None = None
    vex_status: str
    vex_justification: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cra_clauses: list[dict[str, str]] = Field(default_factory=list)


class Art14NotificationDraft(BaseModel):
    """Pre-filled draft for Art. 14(2)(a) early-warning notification."""

    notification_type: str = "early_warning_24h"
    cra_article: str = "Article 14(1) and 14(2)(a)"
    cra_article_verbatim: str = ""
    product_id: str
    product_name: str
    product_version: str
    vulnerability_id: str
    component_purl: str | None = None
    exploitation_evidence_flag: str = "ACTIVELY_EXPLOITED"
    cvss_score: float | None = None
    severity: str | None = None
    scope_note: str = (
        "Submit simultaneously to the coordinator CSIRT and ENISA "
        "via the Single Reporting Platform within 24 hours of discovery. "
        "Follow up with 72h notification (Art. 14(2)(b)) and 14-day final "
        "report (Art. 14(3))."
    )
    generated_by: str = f"cra-sbom-evidence v{__version__}"


class Evidence(BaseModel):
    """The complete CRA evidence pack for one product."""

    tool: str = "cra-sbom-evidence"
    tool_version: str = __version__
    generated_at_utc: str
    regulation: str = "Regulation (EU) 2024/2847"
    art_14_applies_from: str = "2026-09-11"
    product: dict[str, Any]
    sbom_files: list[dict[str, Any]] = Field(default_factory=list)
    vex_files: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[FindingCraMapping] = Field(default_factory=list)
    art14_notification_drafts: list[Art14NotificationDraft] = Field(default_factory=list)
    # Registry snapshot for traceability
    cra_clauses_cited: list[dict[str, str]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _isoformat_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clauses_for_finding(status: str, cvss_score: float | None) -> list[dict[str, str]]:
    """Return the CRA clauses relevant to a given VEX status + severity."""
    clause_keys: list[str] = ["annex_i_part_ii", "art_13_6", "art_13_8"]

    if status in ("affected", "under_investigation"):
        clause_keys.append("art_14_1")
        clause_keys.append("art_14_2")
        if cvss_score is not None and cvss_score >= 9.0:
            clause_keys.append("art_14_3")
    if status == "fixed":
        clause_keys.append("annex_i_part_ii")  # public disclosure of fixed vulns

    registry = load_registry()
    result: list[dict[str, str]] = []
    for k in dict.fromkeys(clause_keys):  # deduplicate, preserve order
        if k in registry.clauses:
            c = registry.clauses[k]
            result.append({
                "key": k,
                "title": c.title,
                "text_excerpt": c.text[:300] + ("…" if len(c.text) > 300 else ""),
                "source_url": c.source_url,
                "sha256": c.sha256,
            })
    return result


def _build_vex_index(
    vex_statements: list[VexStatement],
) -> dict[str, VexStatement]:
    """Index VEX statements by vulnerability_id for fast lookup.

    When multiple statements exist for the same vulnerability, prefer the one
    with the most specific status (affected > fixed > under_investigation > not_affected).
    """
    status_priority: dict[str, int] = {
        "affected": 4,
        "fixed": 3,
        "under_investigation": 2,
        "not_affected": 1,
    }
    index: dict[str, VexStatement] = {}
    for stmt in vex_statements:
        key = stmt.vulnerability_id
        if key not in index:
            index[key] = stmt
        else:
            existing_priority = status_priority.get(index[key].status, 0)
            new_priority = status_priority.get(stmt.status, 0)
            if new_priority > existing_priority:
                index[key] = stmt
    return index


def _component_by_ref(
    sbom: SbomDocument, bom_ref: str
) -> tuple[str | None, str | None]:
    """Return (name, purl) for a component bom-ref (CycloneDX) or SPDXID."""
    for c in sbom.components:
        if c.bom_ref == bom_ref or c.name == bom_ref:
            return c.name, c.purl
    return None, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_evidence(
    sboms: list[SbomDocument],
    vex_statements: list[VexStatement],
    product: ProductManifest,
    timestamp_iso: str | None = None,
) -> Evidence:
    """Join SBOM + VEX + product into a ``Evidence`` object.

    Args:
        sboms: List of parsed SBOM documents.
        vex_statements: Combined list of parsed VEX statements from all feeds.
        product: Parsed product manifest.
        timestamp_iso: Override generation timestamp (for deterministic tests).

    Returns:
        A fully populated ``Evidence`` instance.
    """
    ts = timestamp_iso or _isoformat_now()
    vex_index = _build_vex_index(vex_statements)

    # Summarise SBOM inputs
    sbom_files: list[dict[str, Any]] = []
    for s in sboms:
        sbom_files.append({
            "format": s.format,
            "spec_version": s.spec_version,
            "source_path": s.source_path,
            "component_count": len(s.components),
            "embedded_vuln_count": len(s.vulnerabilities),
            "metadata_component": s.metadata_component_name,
        })

    # Summarise VEX inputs
    status_counts: dict[str, int] = {
        "affected": 0,
        "fixed": 0,
        "not_affected": 0,
        "under_investigation": 0,
    }
    for stmt in vex_statements:
        status_counts[stmt.status] = status_counts.get(stmt.status, 0) + 1
    vex_files: list[dict[str, Any]] = [
        {
            "statement_count": len(vex_statements),
            "status_counts": status_counts,
        }
    ]

    # Build findings from SBOM-embedded vulns + external VEX overlay
    findings: list[FindingCraMapping] = []
    notification_drafts: list[Art14NotificationDraft] = []
    # Track cited clauses
    cited_keys: set[str] = set()

    # Process all vulns from all SBOMs
    all_sbom_vulns: list[tuple[SbomVulnerability, SbomDocument]] = []
    for sbom in sboms:
        for v in sbom.vulnerabilities:
            all_sbom_vulns.append((v, sbom))

    # Also collect distinct vuln IDs from VEX (may not have SBOM embedding)
    sbom_vuln_ids = {v.vuln_id for v, _ in all_sbom_vulns}
    extra_vex = [
        stmt for stmt in vex_statements
        if stmt.vulnerability_id not in sbom_vuln_ids
    ]

    for vuln, sbom in all_sbom_vulns:
        # Determine VEX status: prefer external VEX, fall back to embedded CycloneDX
        external_vex = vex_index.get(vuln.vuln_id)
        if external_vex is not None:
            effective_status: str = external_vex.status
            justification = external_vex.justification
        else:
            raw_state = vuln.vex_state or "under_investigation"
            effective_status = _CYCLONEDX_TO_VEX_STATUS.get(raw_state, "under_investigation")
            justification = vuln.vex_justification

        # Map back to component name/purl from first affects_ref
        comp_name: str | None = None
        comp_purl: str | None = None
        if vuln.affects_refs:
            ref = vuln.affects_refs[0]
            comp_name, comp_purl = _component_by_ref(sbom, ref)
            if comp_name is None:
                comp_name = ref

        clauses = _clauses_for_finding(effective_status, vuln.score)
        for c in clauses:
            cited_keys.add(c["key"])

        finding = FindingCraMapping(
            vulnerability_id=vuln.vuln_id,
            component_name=comp_name,
            component_purl=comp_purl,
            vex_status=effective_status,
            vex_justification=justification,
            severity=vuln.severity,
            cvss_score=vuln.score,
            cra_clauses=clauses,
        )
        findings.append(finding)

        # Art. 14 draft: triggered for affected + high/critical severity
        _maybe_add_draft(
            finding, product, notification_drafts, ts
        )

    # Extra VEX-only findings
    for stmt in extra_vex:
        clauses = _clauses_for_finding(stmt.status, None)
        for clause_item in clauses:
            cited_keys.add(clause_item["key"])
        finding = FindingCraMapping(
            vulnerability_id=stmt.vulnerability_id,
            component_purl=stmt.product_id,
            vex_status=stmt.status,
            vex_justification=stmt.justification,
            cra_clauses=clauses,
        )
        findings.append(finding)
        _maybe_add_draft(finding, product, notification_drafts, ts)

    # Always cite core CRA clauses even if no findings
    for core_key in ("art_13_1", "annex_i_part_ii", "art_14_1"):
        cited_keys.add(core_key)

    # Build citation list
    registry = load_registry()
    cra_clauses_cited: list[dict[str, str]] = []
    for k in sorted(cited_keys):
        if k in registry.clauses:
            clause_entry = registry.clauses[k]
            cra_clauses_cited.append({
                "key": k,
                "title": clause_entry.title,
                "source_url": clause_entry.source_url,
                "sha256": clause_entry.sha256,
            })

    return Evidence(
        generated_at_utc=ts,
        product={
            "id": product.id,
            "name": product.name,
            "version": product.version,
            "manufacturer": product.manufacturer,
            "eu_representative": product.eu_representative,
            "support_until": product.support_until,
            "annex_iii_classification": product.annex_iii_classification,
            "spoc_email": product.spoc_email,
            "spoc_url": product.spoc_url,
            "cvd_policy_url": product.cvd_policy_url,
        },
        sbom_files=sbom_files,
        vex_files=vex_files,
        findings=findings,
        art14_notification_drafts=notification_drafts,
        cra_clauses_cited=cra_clauses_cited,
    )


# CycloneDX state → VEX status mapping (mirrors vex.py for local use)
_CYCLONEDX_TO_VEX_STATUS: dict[str, str] = {
    "not_affected": "not_affected",
    "resolved": "fixed",
    "false_positive": "not_affected",
    "exploitable": "affected",
    "in_triage": "under_investigation",
}


def _maybe_add_draft(
    finding: FindingCraMapping,
    product: ProductManifest,
    drafts: list[Art14NotificationDraft],
    ts: str,
) -> None:
    """Append an Art. 14 notification draft if the finding is high severity + affected."""
    if finding.vex_status not in ("affected",):
        return
    score_trigger = (
        finding.cvss_score is not None and finding.cvss_score >= _ART14_SCORE_THRESHOLD
    )
    sev_trigger = (finding.severity or "").lower() in _HIGH_SEVERITY_LABELS
    if not (score_trigger or sev_trigger):
        return

    try:
        art14_clause = get_clause("art_14_1")
        verbatim = art14_clause.text
    except KeyError:
        verbatim = ""

    drafts.append(
        Art14NotificationDraft(
            product_id=product.id,
            product_name=product.name,
            product_version=product.version,
            vulnerability_id=finding.vulnerability_id,
            component_purl=finding.component_purl,
            cvss_score=finding.cvss_score,
            severity=finding.severity,
            cra_article_verbatim=verbatim,
        )
    )
