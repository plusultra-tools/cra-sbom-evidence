#!/usr/bin/env python3
"""Build clauses.lock from the current cra_clauses.yaml.

The lock file is the canonical SHA-256 source-of-truth for every clause
text that is bundled with the package. ``cra-sbom verify-citations``
compares the YAML at runtime against this lock to detect drift.

Workflow:
1. Maintainer edits ``data/cra_clauses.yaml`` (e.g., to add a clause or
   correct a transcription error). Each edit MUST be verified against
   an authoritative source (EUR-Lex, OJEU PDF).
2. Maintainer runs ``python scripts/build_clauses_lock.py`` to regenerate
   ``data/clauses.lock``.
3. Maintainer commits BOTH files together. CI re-validates the lock
   against the YAML on every push.
4. If a downstream user reports drift, ``cra-sbom verify-citations``
   will fail loudly with a clear diff between the YAML hash and the
   locked hash, AND the user can manually diff the YAML against the
   canonical EUR-Lex text — the lock is the contract.

This script is run by maintainers only. End users should never need
to regenerate the lock.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    raise SystemExit(2) from exc


REPO_ROOT = Path(__file__).resolve().parent.parent
YAML_PATH = REPO_ROOT / "src" / "cra_sbom_evidence" / "data" / "cra_clauses.yaml"
LOCK_PATH = REPO_ROOT / "src" / "cra_sbom_evidence" / "data" / "clauses.lock"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_lock_content(yaml_data: dict[str, Any]) -> str:
    """Build the lock file content from parsed YAML data.

    Format (line-oriented, like a .sha256sum file):
        <sha256>  <clause_key>  <excerpt_type>

    Lines are sorted by clause_key for deterministic output. A header
    comment records the lock-format version and the source YAML name.
    """
    clauses: dict[str, Any] = yaml_data.get("clauses", {})
    lines: list[str] = [
        "# cra_clauses.lock — canonical SHA-256 of each bundled CRA clause text.",
        "# Format: <sha256>  <clause_key>  <excerpt_type>",
        "# Source YAML: src/cra_sbom_evidence/data/cra_clauses.yaml",
        "# Regenerate via: python scripts/build_clauses_lock.py",
        "# Verify at runtime via: cra-sbom verify-citations",
        "",
    ]
    for key in sorted(clauses):
        clause = clauses[key]
        if not isinstance(clause, dict):
            continue
        text = clause.get("text", "")
        excerpt_type = clause.get("excerpt_type", "verbatim")
        digest = _sha256_text(text)
        lines.append(f"{digest}  {key}  {excerpt_type}")
    return "\n".join(lines) + "\n"


def main() -> int:
    if not YAML_PATH.exists():
        print(f"ERROR: YAML not found: {YAML_PATH}", file=sys.stderr)
        return 1
    with YAML_PATH.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    content = build_lock_content(data)
    LOCK_PATH.write_text(content, encoding="utf-8")
    clause_count = content.count("\n") - 6   # exclude header
    print(f"OK: wrote {LOCK_PATH} ({clause_count} clauses).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
