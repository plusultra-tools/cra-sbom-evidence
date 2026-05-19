"""CLI entrypoint: ``cra-sbom evidence`` and ``cra-sbom verify``.

Exit codes:
  0 — success
  1 — missing / unreadable inputs
  2 — parse error in SBOM/VEX/product
  3 — hash mismatch (verify command)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cra_sbom_evidence import __version__
from cra_sbom_evidence.audit import write_audit_chain, verify_audit_chain
from cra_sbom_evidence.cra_text import verify_integrity
from cra_sbom_evidence.evidence import build_evidence
from cra_sbom_evidence.product import parse_product
from cra_sbom_evidence.renderer import render_evidence_markdown
from cra_sbom_evidence.sbom import parse_sbom, SbomDocument
from cra_sbom_evidence.vex import parse_vex, VexStatement

EVIDENCE_JSON = "cra_evidence.json"
EVIDENCE_MD = "cra_evidence.md"
AUDIT_FILE = "audit.sha256"


# ---------------------------------------------------------------------------
# Sub-command: evidence
# ---------------------------------------------------------------------------


def _cmd_evidence(args: argparse.Namespace) -> int:
    """Run the evidence generation pipeline."""
    # Resolve SBOM paths
    sbom_paths: list[str] = []
    for raw in (args.sbom or "").split(","):
        p = raw.strip()
        if p:
            sbom_paths.append(p)

    if not sbom_paths:
        print("ERROR: at least one --sbom path is required.", file=sys.stderr)
        return 1

    for p in sbom_paths:
        if not Path(p).exists():
            print(f"ERROR: SBOM file not found: {p}", file=sys.stderr)
            return 1

    # Resolve product manifest
    if not args.product:
        print("ERROR: --product manifest path is required.", file=sys.stderr)
        return 1
    if not Path(args.product).exists():
        print(f"ERROR: product manifest not found: {args.product}", file=sys.stderr)
        return 1

    # Parse SBOMs
    sboms: list[SbomDocument] = []
    for p in sbom_paths:
        try:
            sboms.append(parse_sbom(p))
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"ERROR: could not parse SBOM {p!r}: {exc}", file=sys.stderr)
            return 2

    # Parse VEX feeds (optional)
    vex_statements: list[VexStatement] = []
    vex_paths: list[str] = []
    if args.vex:
        for raw in args.vex.split(","):
            p = raw.strip()
            if not p:
                continue
            if not Path(p).exists():
                print(f"ERROR: VEX file not found: {p}", file=sys.stderr)
                return 1
            try:
                stmts = parse_vex(p)
                vex_statements.extend(stmts)
                vex_paths.append(p)
            except (json.JSONDecodeError, ValueError) as exc:
                print(f"ERROR: could not parse VEX {p!r}: {exc}", file=sys.stderr)
                return 2

    # Parse product manifest
    try:
        product = parse_product(args.product)
    except (ValueError, Exception) as exc:
        print(f"ERROR: could not parse product manifest: {exc}", file=sys.stderr)
        return 2

    # Build evidence
    evidence = build_evidence(sboms, vex_statements, product)

    # Prepare output directory
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write evidence JSON
    json_path = out_dir / EVIDENCE_JSON
    evidence_dict = evidence.model_dump()
    json_text = json.dumps(evidence_dict, indent=2, sort_keys=True)
    json_path.write_text(json_text, encoding="utf-8")

    # Write evidence Markdown
    md_path = out_dir / EVIDENCE_MD
    md_text = render_evidence_markdown(evidence)
    md_path.write_text(md_text, encoding="utf-8")

    # Write audit chain
    input_paths: list[str] = sbom_paths + vex_paths + [args.product]
    output_paths: list[str] = [str(json_path), str(md_path)]
    audit_sha = write_audit_chain(out_dir, input_paths, output_paths)

    print(f"OK: evidence pack written to {out_dir}/")
    print(f"  {json_path.name}  (sha256 prefix={_hex(str(json_path))[:12]}...)")
    print(f"  {md_path.name}  (sha256 prefix={_hex(str(md_path))[:12]}...)")
    print(f"  {AUDIT_FILE}  (chain sha256={audit_sha[:12]}...)")
    print(f"Findings: {len(evidence.findings)}")
    print(f"Art. 14 drafts: {len(evidence.art14_notification_drafts)}")
    print(f"CRA clauses cited: {len(evidence.cra_clauses_cited)}")
    return 0


# ---------------------------------------------------------------------------
# Sub-command: verify
# ---------------------------------------------------------------------------


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify the audit chain of a previously generated evidence pack."""
    if not args.evidence_pack:
        print("ERROR: --evidence-pack path is required.", file=sys.stderr)
        return 1

    pack_dir = Path(args.evidence_pack)
    audit_path = pack_dir / AUDIT_FILE
    if not audit_path.exists():
        print(f"ERROR: audit file not found: {audit_path}", file=sys.stderr)
        return 1

    result = verify_audit_chain(audit_path)
    if result.get("ok"):
        print("OK: audit chain verified — all hashes match.")
        return 0
    else:
        print("FAIL: audit chain verification failed.")
        for entry in result.get("entries", []):
            if not entry.get("ok"):
                print(f"  MISMATCH: {entry.get('label', '')} — "
                      f"stored={entry.get('stored', '')[:12]}... "
                      f"actual={entry.get('actual', '')[:12]}...",
                      file=sys.stderr)
        if not result.get("chain_ok"):
            print("  CHAIN hash mismatch.", file=sys.stderr)
        return 3


# ---------------------------------------------------------------------------
# Sub-command: verify-citations
# ---------------------------------------------------------------------------


def _cmd_verify_citations(_args: argparse.Namespace) -> int:
    """Verify each bundled CRA clause text against the canonical clauses.lock.

    The lock file is the source-of-truth; the YAML is verified against it.
    Drift in the YAML (transcription error, accidental edit) surfaces as a
    non-zero exit code.
    """
    results = verify_integrity()
    all_ok = all(entry["status"] == "ok" for entry in results.values())
    for key in sorted(results):
        entry = results[key]
        status = entry["status"]
        if status == "ok":
            label = "OK"
        elif status == "drift":
            label = "DRIFT"
        elif status == "type_drift":
            label = "TYPE-DRIFT"
        elif status == "missing_in_lock":
            label = "NEW-IN-YAML"
        elif status == "missing_in_yaml":
            label = "MISSING-IN-YAML"
        else:
            label = status.upper()
        print(f"  {label}: {key}")
        if status in ("drift", "type_drift"):
            print(
                f"      yaml_sha256={entry['yaml_sha256'][:16]}... "
                f"lock_sha256={entry['lock_sha256'][:16]}..."
            )
            if status == "type_drift":
                print(
                    f"      yaml_excerpt_type={entry['yaml_excerpt_type']!r} "
                    f"lock_excerpt_type={entry['lock_excerpt_type']!r}"
                )
    if all_ok:
        print(f"OK: all {len(results)} clause texts match clauses.lock.")
        return 0
    else:
        drifted = [k for k, e in results.items() if e["status"] != "ok"]
        print(
            f"FAIL: {len(drifted)} clause(s) do not match clauses.lock: {drifted}",
            file=sys.stderr,
        )
        return 3


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cra-sbom",
        description=(
            "CRA Article 14 evidence pack generator. "
            "Produces verbatim-cited, hash-chained compliance artifacts "
            "from CycloneDX/SPDX SBOMs and OpenVEX/CSAF VEX feeds."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"cra-sbom-evidence {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # evidence sub-command
    ev = sub.add_parser(
        "evidence",
        help="Generate CRA evidence pack from SBOM + VEX + product manifest.",
    )
    ev.add_argument(
        "--sbom",
        required=True,
        help="Comma-separated path(s) to SBOM JSON file(s) (CycloneDX or SPDX).",
    )
    ev.add_argument(
        "--vex",
        default=None,
        help="Comma-separated path(s) to VEX JSON file(s) (OpenVEX or CSAF 2.0). Optional.",
    )
    ev.add_argument(
        "--product",
        required=True,
        help="Path to product manifest YAML file.",
    )
    ev.add_argument(
        "--out",
        default="evidence-pack",
        help="Output directory for evidence pack (default: evidence-pack/).",
    )

    # verify sub-command
    ve = sub.add_parser(
        "verify",
        help="Verify the audit chain of a previously generated evidence pack.",
    )
    ve.add_argument(
        "--evidence-pack",
        required=True,
        help="Path to the evidence pack directory containing audit.sha256.",
    )

    # verify-citations sub-command
    sub.add_parser(
        "verify-citations",
        help="Verify the SHA-256 integrity of all bundled CRA clause texts.",
    )

    return parser


def _hex(path: str) -> str:
    """Quick sha256 of a file path for display purposes."""
    from cra_sbom_evidence.audit import sha256_file
    try:
        return sha256_file(path)
    except FileNotFoundError:
        return "000000000000"


def main(argv: list[str] | None = None) -> int:
    """Main entry point. Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "evidence":
        return _cmd_evidence(args)
    elif args.command == "verify":
        return _cmd_verify(args)
    elif args.command == "verify-citations":
        return _cmd_verify_citations(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
