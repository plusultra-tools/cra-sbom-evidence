"""Tests for src/cra_sbom_evidence/vex.py."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from cra_sbom_evidence.vex import parse_vex

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseOpenVEX:
    def test_basic_parse(self) -> None:
        stmts = parse_vex(FIXTURES / "openvex-sample.json")
        assert len(stmts) == 2

    def test_not_affected_statement(self) -> None:
        stmts = parse_vex(FIXTURES / "openvex-sample.json")
        na = next(s for s in stmts if s.vulnerability_id == "CVE-2024-0001")
        assert na.status == "not_affected"
        assert na.justification == "vulnerable_code_not_in_execute_path"
        assert na.source_format == "OpenVEX"

    def test_affected_statement(self) -> None:
        stmts = parse_vex(FIXTURES / "openvex-sample.json")
        aff = next(s for s in stmts if s.vulnerability_id == "CVE-2024-0002")
        assert aff.status == "affected"
        assert aff.action_statement is not None
        assert "libexpat" in aff.action_statement.lower() or "patch" in aff.action_statement.lower()

    def test_product_id_extracted(self) -> None:
        stmts = parse_vex(FIXTURES / "openvex-sample.json")
        na = next(s for s in stmts if s.vulnerability_id == "CVE-2024-0001")
        assert "openssl" in na.product_id

    def test_timestamp_inherited_from_doc(self) -> None:
        stmts = parse_vex(FIXTURES / "openvex-sample.json")
        for s in stmts:
            assert s.timestamp == "2026-06-18T09:00:00Z"


class TestParseCSAF:
    def test_basic_parse(self) -> None:
        stmts = parse_vex(FIXTURES / "csaf-vex-sample.json")
        assert len(stmts) >= 2

    def test_fixed_status(self) -> None:
        stmts = parse_vex(FIXTURES / "csaf-vex-sample.json")
        fixed = next(s for s in stmts if s.vulnerability_id == "CVE-2024-0003")
        assert fixed.status == "fixed"
        assert fixed.source_format == "CSAF"

    def test_not_affected_status(self) -> None:
        stmts = parse_vex(FIXTURES / "csaf-vex-sample.json")
        na = next(s for s in stmts if s.vulnerability_id == "CVE-2024-0004")
        assert na.status == "not_affected"

    def test_justification_from_flags(self) -> None:
        stmts = parse_vex(FIXTURES / "csaf-vex-sample.json")
        na = next(s for s in stmts if s.vulnerability_id == "CVE-2024-0004")
        assert na.justification == "component_not_present"

    def test_action_statement_from_remediation(self) -> None:
        stmts = parse_vex(FIXTURES / "csaf-vex-sample.json")
        fixed = next(s for s in stmts if s.vulnerability_id == "CVE-2024-0003")
        assert fixed.action_statement is not None
        assert "my-product" in fixed.action_statement.lower()

    def test_timestamp_from_document(self) -> None:
        stmts = parse_vex(FIXTURES / "csaf-vex-sample.json")
        for s in stmts:
            assert s.timestamp is not None


class TestParseErrors:
    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_vex("/nonexistent/vex.json")

    def test_unknown_format(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            json.dump({"unknown_key": "value"}, f)
            path = f.name
        with pytest.raises(ValueError, match="Unrecognised VEX format"):
            parse_vex(path)

    def test_not_a_dict(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            json.dump([1, 2, 3], f)
            path = f.name
        with pytest.raises(ValueError):
            parse_vex(path)
