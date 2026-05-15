"""Tests for src/cra_sbom_evidence/evidence.py."""
from __future__ import annotations

from pathlib import Path


from cra_sbom_evidence.evidence import Evidence, build_evidence
from cra_sbom_evidence.product import parse_product
from cra_sbom_evidence.sbom import parse_sbom
from cra_sbom_evidence.vex import parse_vex

FIXTURES = Path(__file__).parent / "fixtures"
TS = "2026-06-18T09:00:00Z"  # fixed timestamp for deterministic tests


def _get_evidence() -> Evidence:
    sbom = parse_sbom(FIXTURES / "cyclonedx-sample.json")
    vex = parse_vex(FIXTURES / "openvex-sample.json")
    product = parse_product(FIXTURES / "product.yaml")
    return build_evidence([sbom], vex, product, timestamp_iso=TS)


class TestBuildEvidence:
    def test_returns_evidence(self) -> None:
        ev = _get_evidence()
        assert isinstance(ev, Evidence)

    def test_tool_version_present(self) -> None:
        ev = _get_evidence()
        assert ev.tool == "cra-sbom-evidence"
        assert ev.tool_version

    def test_generated_at_matches_injection(self) -> None:
        ev = _get_evidence()
        assert ev.generated_at_utc == TS

    def test_product_fields(self) -> None:
        ev = _get_evidence()
        assert ev.product["name"] == "My Product"
        assert ev.product["manufacturer"] == "Example Corp"
        assert ev.product["id"] == "my-product-v1.2.3"

    def test_sbom_files_summary(self) -> None:
        ev = _get_evidence()
        assert len(ev.sbom_files) == 1
        s = ev.sbom_files[0]
        assert s["format"] == "CycloneDX"
        assert s["component_count"] == 2

    def test_vex_summary(self) -> None:
        ev = _get_evidence()
        assert len(ev.vex_files) == 1
        v = ev.vex_files[0]
        assert v["statement_count"] == 2

    def test_findings_present(self) -> None:
        ev = _get_evidence()
        assert len(ev.findings) > 0

    def test_findings_have_cra_clauses(self) -> None:
        ev = _get_evidence()
        for f in ev.findings:
            assert len(f.cra_clauses) > 0

    def test_clauses_cited(self) -> None:
        ev = _get_evidence()
        cited_keys = {c["key"] for c in ev.cra_clauses_cited}
        # Core clauses always cited
        assert "art_13_1" in cited_keys
        assert "annex_i_part_ii" in cited_keys

    def test_art14_draft_for_critical(self) -> None:
        # CVE-2024-0002 is critical + exploitable → should trigger Art.14 draft
        ev = _get_evidence()
        draft_vulns = {d.vulnerability_id for d in ev.art14_notification_drafts}
        assert "CVE-2024-0002" in draft_vulns

    def test_art14_draft_has_verbatim_clause(self) -> None:
        ev = _get_evidence()
        if ev.art14_notification_drafts:
            draft = ev.art14_notification_drafts[0]
            assert len(draft.cra_article_verbatim) > 10

    def test_no_draft_for_not_affected(self) -> None:
        # CVE-2024-0001 is not_affected (via external VEX) → no Art.14 draft
        ev = _get_evidence()
        draft_vulns = {d.vulnerability_id for d in ev.art14_notification_drafts}
        assert "CVE-2024-0001" not in draft_vulns

    def test_regulation_field(self) -> None:
        ev = _get_evidence()
        assert "2024/2847" in ev.regulation

    def test_art14_applies_from(self) -> None:
        ev = _get_evidence()
        assert ev.art_14_applies_from == "2026-09-11"


class TestBuildEvidenceMultipleSbom:
    def test_spdx_and_cyclonedx(self) -> None:
        cdx = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        spdx = parse_sbom(FIXTURES / "spdx-sample.json")
        product = parse_product(FIXTURES / "product.yaml")
        ev = build_evidence([cdx, spdx], [], product, timestamp_iso=TS)
        assert len(ev.sbom_files) == 2
        formats = {s["format"] for s in ev.sbom_files}
        assert "CycloneDX" in formats
        assert "SPDX" in formats


class TestBuildEvidenceEmptyVex:
    def test_no_vex_still_works(self) -> None:
        sbom = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        product = parse_product(FIXTURES / "product.yaml")
        ev = build_evidence([sbom], [], product, timestamp_iso=TS)
        assert isinstance(ev, Evidence)
        # With no external VEX, embedded CycloneDX states used
        assert len(ev.findings) > 0
