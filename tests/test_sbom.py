"""Tests for src/cra_sbom_evidence/sbom.py."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from cra_sbom_evidence.sbom import parse_sbom

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseCycloneDX:
    def test_basic_parse(self) -> None:
        doc = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        assert doc.format == "CycloneDX"
        assert doc.spec_version == "1.5"
        assert doc.serial_number == "urn:uuid:1a2b3c4d-0000-0000-0000-000000000001"

    def test_components(self) -> None:
        doc = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        assert len(doc.components) == 2
        names = {c.name for c in doc.components}
        assert "openssl" in names
        assert "libexpat" in names

    def test_component_fields(self) -> None:
        doc = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        openssl = next(c for c in doc.components if c.name == "openssl")
        assert openssl.purl == "pkg:generic/openssl@3.2.1"
        assert openssl.version == "3.2.1"
        assert "Apache-2.0" in openssl.licenses
        assert openssl.supplier == "OpenSSL Project"

    def test_embedded_vulnerabilities(self) -> None:
        doc = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        assert len(doc.vulnerabilities) == 2
        ids = {v.vuln_id for v in doc.vulnerabilities}
        assert "CVE-2024-0001" in ids
        assert "CVE-2024-0002" in ids

    def test_vuln_not_affected(self) -> None:
        doc = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        v = next(x for x in doc.vulnerabilities if x.vuln_id == "CVE-2024-0001")
        assert v.vex_state == "not_affected"
        assert v.vex_justification == "vulnerable_code_not_in_execute_path"
        assert v.score == 7.5
        assert v.severity == "high"

    def test_vuln_exploitable(self) -> None:
        doc = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        v = next(x for x in doc.vulnerabilities if x.vuln_id == "CVE-2024-0002")
        assert v.vex_state == "exploitable"
        assert v.score == 9.1
        assert v.severity == "critical"

    def test_metadata_component(self) -> None:
        doc = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        assert doc.metadata_component_name == "my-product"
        assert doc.metadata_component_version == "1.2.3"

    def test_created_at(self) -> None:
        doc = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        assert doc.created_at == "2026-06-18T09:00:00Z"

    def test_source_path_recorded(self) -> None:
        doc = parse_sbom(FIXTURES / "cyclonedx-sample.json")
        assert doc.source_path is not None


class TestParseSPDX:
    def test_basic_parse(self) -> None:
        doc = parse_sbom(FIXTURES / "spdx-sample.json")
        assert doc.format == "SPDX"
        assert "2.3" in doc.spec_version

    def test_components(self) -> None:
        doc = parse_sbom(FIXTURES / "spdx-sample.json")
        names = {c.name for c in doc.components}
        assert "openssl" in names
        assert "zlib" in names

    def test_purl_extracted(self) -> None:
        doc = parse_sbom(FIXTURES / "spdx-sample.json")
        openssl = next(c for c in doc.components if c.name == "openssl")
        assert openssl.purl == "pkg:generic/openssl@3.2.1"

    def test_license_extracted(self) -> None:
        doc = parse_sbom(FIXTURES / "spdx-sample.json")
        openssl = next(c for c in doc.components if c.name == "openssl")
        assert "Apache-2.0" in openssl.licenses

    def test_doc_namespace(self) -> None:
        doc = parse_sbom(FIXTURES / "spdx-sample.json")
        assert doc.doc_namespace == "https://example.com/spdx/my-product/1.2.3"

    def test_created_at(self) -> None:
        doc = parse_sbom(FIXTURES / "spdx-sample.json")
        assert doc.created_at == "2026-06-18T09:00:00Z"


class TestParseErrors:
    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_sbom("/nonexistent/sbom.json")

    def test_unknown_format(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            json.dump({"unknown_key": "value"}, f)
            path = f.name
        with pytest.raises(ValueError, match="Unrecognised SBOM format"):
            parse_sbom(path)

    def test_not_a_dict(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as f:
            json.dump([1, 2, 3], f)
            path = f.name
        with pytest.raises(ValueError):
            parse_sbom(path)
