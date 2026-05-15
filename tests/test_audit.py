"""Tests for src/cra_sbom_evidence/audit.py."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from cra_sbom_evidence.audit import (
    AUDIT_FILENAME,
    build_audit_chain,
    sha256_file,
    sha256_text,
    verify_audit_chain,
    write_audit_chain,
)


def _write_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


class TestSha256:
    def test_text_consistent(self) -> None:
        h1 = sha256_text("hello")
        h2 = sha256_text("hello")
        assert h1 == h2

    def test_text_known_value(self) -> None:
        # sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert sha256_text("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_file_consistent(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write("test content")
            path = f.name
        h1 = sha256_file(path)
        h2 = sha256_file(path)
        assert h1 == h2

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            sha256_file("/nonexistent/file.txt")

    def test_file_matches_text(self) -> None:
        content = "hello world"
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".txt", delete=False
        ) as f:
            f.write(content.encode("utf-8"))
            path = f.name
        assert sha256_file(path) == sha256_text(content)


class TestBuildAuditChain:
    def test_chain_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "input.json"
            out = Path(tmp) / "output.md"
            _write_file(inp, '{"test": true}')
            _write_file(out, "# Test")
            chain = build_audit_chain([inp], [out])
        lines = [ln for ln in chain.splitlines() if ln.strip()]
        assert any("INPUT:input.json" in ln for ln in lines)
        assert any("OUTPUT:output.md" in ln for ln in lines)
        assert any("CHAIN" in ln for ln in lines)

    def test_chain_hash_is_valid_hex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "a.txt"
            _write_file(inp, "content")
            chain = build_audit_chain([inp], [])
        chain_line = [ln for ln in chain.splitlines() if "CHAIN" in ln][0]
        chain_hash = chain_line.split("  ")[0].strip()
        assert len(chain_hash) == 64
        int(chain_hash, 16)  # must be valid hex

    def test_deterministic_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "a.txt"
            _write_file(inp, "hello")
            c1 = build_audit_chain([inp], [])
            c2 = build_audit_chain([inp], [])
        assert c1 == c2


class TestWriteAndVerify:
    def test_write_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "sbom.json"
            out = Path(tmp) / "evidence.json"
            _write_file(inp, '{"format": "CycloneDX"}')
            _write_file(out, '{"result": "ok"}')
            write_audit_chain(tmp, [inp], [out])
            audit_path = Path(tmp) / AUDIT_FILENAME
            assert audit_path.exists()

    def test_verify_passes_on_fresh_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "sbom.json"
            out = Path(tmp) / "evidence.json"
            _write_file(inp, '{"format": "CycloneDX"}')
            _write_file(out, '{"result": "ok"}')
            write_audit_chain(tmp, [inp], [out])
            result = verify_audit_chain(Path(tmp) / AUDIT_FILENAME)
            assert result["ok"] is True
            assert result["chain_ok"] is True

    def test_verify_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "sbom.json"
            out = Path(tmp) / "evidence.json"
            _write_file(inp, '{"format": "CycloneDX"}')
            _write_file(out, '{"result": "ok"}')
            write_audit_chain(tmp, [inp], [out])
            # Tamper with the output file
            _write_file(out, '{"result": "tampered"}')
            result = verify_audit_chain(Path(tmp) / AUDIT_FILENAME)
            assert result["ok"] is False

    def test_verify_audit_not_found(self) -> None:
        result = verify_audit_chain("/nonexistent/audit.sha256")
        assert result["ok"] is False
