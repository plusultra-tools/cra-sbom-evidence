"""Tests for src/cra_sbom_evidence/cli.py."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from cra_sbom_evidence.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class TestEvidenceCommand:
    def test_basic_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = main([
                "evidence",
                "--sbom", str(FIXTURES / "cyclonedx-sample.json"),
                "--vex", str(FIXTURES / "openvex-sample.json"),
                "--product", str(FIXTURES / "product.yaml"),
                "--out", tmp,
            ])
            assert rc == 0
            assert (Path(tmp) / "cra_evidence.json").exists()
            assert (Path(tmp) / "cra_evidence.md").exists()
            assert (Path(tmp) / "audit.sha256").exists()

    def test_json_output_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            main([
                "evidence",
                "--sbom", str(FIXTURES / "cyclonedx-sample.json"),
                "--product", str(FIXTURES / "product.yaml"),
                "--out", tmp,
            ])
            data = json.loads((Path(tmp) / "cra_evidence.json").read_text())
            assert data["tool"] == "cra-sbom-evidence"
            assert "product" in data
            assert "findings" in data

    def test_spdx_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = main([
                "evidence",
                "--sbom", str(FIXTURES / "spdx-sample.json"),
                "--product", str(FIXTURES / "product.yaml"),
                "--out", tmp,
            ])
            assert rc == 0

    def test_csaf_vex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = main([
                "evidence",
                "--sbom", str(FIXTURES / "cyclonedx-sample.json"),
                "--vex", str(FIXTURES / "csaf-vex-sample.json"),
                "--product", str(FIXTURES / "product.yaml"),
                "--out", tmp,
            ])
            assert rc == 0

    def test_missing_sbom_returns_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = main([
                "evidence",
                "--sbom", str(FIXTURES / "cyclonedx-sample.json"),
                "--product", "/nonexistent/product.yaml",
                "--out", tmp,
            ])
            assert rc == 1

    def test_nonexistent_sbom_returns_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = main([
                "evidence",
                "--sbom", "/nonexistent/sbom.json",
                "--product", str(FIXTURES / "product.yaml"),
                "--out", tmp,
            ])
            assert rc == 1

    def test_no_sbom_flag_prints_error(self) -> None:
        with pytest.raises(SystemExit):
            main(["evidence", "--product", str(FIXTURES / "product.yaml"), "--out", "/tmp"])

    def test_multiple_sboms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = main([
                "evidence",
                "--sbom", f"{FIXTURES / 'cyclonedx-sample.json'},{FIXTURES / 'spdx-sample.json'}",
                "--product", str(FIXTURES / "product.yaml"),
                "--out", tmp,
            ])
            assert rc == 0
            data = json.loads((Path(tmp) / "cra_evidence.json").read_text())
            assert len(data["sbom_files"]) == 2


class TestVerifyCommand:
    def test_verify_fresh_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            main([
                "evidence",
                "--sbom", str(FIXTURES / "cyclonedx-sample.json"),
                "--product", str(FIXTURES / "product.yaml"),
                "--out", tmp,
            ])
            rc = main(["verify", "--evidence-pack", tmp])
            assert rc == 0

    def test_verify_missing_pack(self) -> None:
        rc = main(["verify", "--evidence-pack", "/nonexistent/pack"])
        assert rc == 1


class TestVerifyCitationsCommand:
    def test_citations_pass(self) -> None:
        rc = main(["verify-citations"])
        assert rc == 0


class TestVersionFlag:
    def test_version(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
