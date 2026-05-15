"""VEX feed parser — OpenVEX 0.2.0+ and CSAF 2.0 VEX.

Normalises both formats into a common ``VexStatement`` list.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

VexStatus = Literal["not_affected", "affected", "fixed", "under_investigation"]

_CYCLONEDX_TO_VEX: dict[str, VexStatus] = {
    "not_affected": "not_affected",
    "resolved": "fixed",
    "false_positive": "not_affected",
    "exploitable": "affected",
    "in_triage": "under_investigation",
}

_CSAF_TO_VEX: dict[str, VexStatus] = {
    "known_not_affected": "not_affected",
    "known_affected": "affected",
    "fixed": "fixed",
    "under_investigation": "under_investigation",
    "first_fixed": "fixed",
    "first_affected": "affected",
    "last_affected": "affected",
    "recommended": "fixed",
}


class VexStatement(BaseModel):
    """A single VEX disposition for one (vulnerability, product) pair."""

    vulnerability_id: str
    product_id: str
    status: VexStatus
    justification: str | None = None
    action_statement: str | None = None
    timestamp: str | None = None
    source_format: str | None = None  # "OpenVEX" | "CSAF" | "CycloneDX"


# ---------------------------------------------------------------------------
# OpenVEX parser
# ---------------------------------------------------------------------------


def _parse_openvex(data: dict[str, Any]) -> list[VexStatement]:
    """Parse an OpenVEX 0.2.0+ JSON document."""
    statements: list[VexStatement] = []
    for stmt in data.get("statements", []):
        if not isinstance(stmt, dict):
            continue
        vuln: dict[str, Any] = stmt.get("vulnerability", {})
        vuln_id: str = str(vuln.get("name") or vuln.get("id") or "")

        raw_status: str = str(stmt.get("status", "under_investigation")).lower()
        # OpenVEX statuses already match our vocabulary
        status: VexStatus
        if raw_status in ("not_affected",):
            status = "not_affected"
        elif raw_status in ("affected",):
            status = "affected"
        elif raw_status in ("fixed",):
            status = "fixed"
        else:
            status = "under_investigation"

        products: list[Any] = stmt.get("products", [])
        for prod in products:
            if isinstance(prod, dict):
                product_id = str(prod.get("@id") or prod.get("id") or "")
            else:
                product_id = str(prod)
            statements.append(
                VexStatement(
                    vulnerability_id=vuln_id,
                    product_id=product_id,
                    status=status,
                    justification=stmt.get("justification"),
                    action_statement=stmt.get("action_statement"),
                    timestamp=stmt.get("timestamp") or data.get("timestamp"),
                    source_format="OpenVEX",
                )
            )
    return statements


# ---------------------------------------------------------------------------
# CSAF 2.0 VEX parser
# ---------------------------------------------------------------------------


def _parse_csaf(data: dict[str, Any]) -> list[VexStatement]:
    """Parse a CSAF 2.0 VEX JSON document."""
    statements: list[VexStatement] = []

    # Build a product-ID → name index from product_tree
    product_tree: dict[str, Any] = data.get("product_tree", {})
    branches: list[Any] = product_tree.get("branches", [])
    prod_index: dict[str, str] = {}
    _index_branches(branches, prod_index)
    for fp in product_tree.get("full_product_names", []):
        if isinstance(fp, dict):
            pid = str(fp.get("product_id") or "")
            prod_index[pid] = str(fp.get("name") or pid)

    doc_tracking: dict[str, Any] = data.get("document", {}).get("tracking", {})
    doc_timestamp: str | None = doc_tracking.get("current_release_date")

    for vuln_block in data.get("vulnerabilities", []):
        if not isinstance(vuln_block, dict):
            continue
        vuln_id: str = str(
            vuln_block.get("cve")
            or (vuln_block.get("ids") or [{}])[0].get("text", "")
        )
        product_status: dict[str, Any] = vuln_block.get("product_status", {})
        flags: list[dict[str, Any]] = vuln_block.get("flags", [])
        flag_map: dict[str, str] = {}
        for flag in flags:
            justification = flag.get("label", "")
            for pid in flag.get("product_ids", []):
                flag_map[pid] = str(justification)

        # Collect remediations for action_statement
        remediations: list[dict[str, Any]] = vuln_block.get("remediations", [])
        remediation_map: dict[str, str] = {}
        for rem in remediations:
            details = rem.get("details", "")
            for pid in rem.get("product_ids", []):
                remediation_map[pid] = str(details)

        for csaf_status, prod_ids in product_status.items():
            vex_status = _CSAF_TO_VEX.get(csaf_status.lower(), "under_investigation")
            for pid in prod_ids or []:
                statements.append(
                    VexStatement(
                        vulnerability_id=vuln_id,
                        product_id=str(pid),
                        status=vex_status,
                        justification=flag_map.get(pid),
                        action_statement=remediation_map.get(pid),
                        timestamp=doc_timestamp,
                        source_format="CSAF",
                    )
                )
    return statements


def _index_branches(branches: list[Any], index: dict[str, str]) -> None:
    """Recursively index product IDs from CSAF product_tree.branches."""
    for branch in branches:
        if not isinstance(branch, dict):
            continue
        product_val: Any = branch.get("product")
        if isinstance(product_val, dict):
            pid = str(product_val.get("product_id") or "")
            name = str(product_val.get("name") or pid)
            index[pid] = name
        sub: list[Any] = branch.get("branches", [])
        if sub:
            _index_branches(sub, index)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_vex(path: str | Path) -> list[VexStatement]:
    """Parse a VEX feed from a JSON file (OpenVEX or CSAF 2.0).

    Detection logic:
    - OpenVEX: ``@context`` contains ``openvex.dev``
    - CSAF 2.0: ``document.category`` is ``"csaf_vex"`` or ``"csaf_security_advisory"``

    Args:
        path: Path to the JSON VEX file.

    Returns:
        A list of normalised ``VexStatement`` objects.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the format is not recognised.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"VEX file not found: {p}")
    with p.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"VEX must be a JSON object, got: {type(data).__name__}")

    context: str = str(data.get("@context", ""))
    if "openvex.dev" in context:
        return _parse_openvex(data)

    doc_section: dict[str, Any] = data.get("document", {})
    category: str = str(doc_section.get("category", "")).lower()
    if category in ("csaf_vex", "csaf_security_advisory", "vex"):
        return _parse_csaf(data)

    # Fallback: try both parsers based on key presence
    if "statements" in data:
        return _parse_openvex(data)
    if "vulnerabilities" in data and "document" in data:
        return _parse_csaf(data)

    raise ValueError(
        "Unrecognised VEX format: expected OpenVEX (@context contains openvex.dev) "
        "or CSAF 2.0 (document.category == 'csaf_vex'). "
        f"Keys found: {list(data.keys())[:10]}"
    )
