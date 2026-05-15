"""Markdown renderer for the CRA evidence pack.

Produces a human-readable ``cra_evidence.md`` from an ``Evidence`` model.
No external templating dependency — pure Python string building.
"""
from __future__ import annotations

from typing import Any

from cra_sbom_evidence.evidence import Evidence


def render_evidence_markdown(evidence: Evidence) -> str:
    """Render an ``Evidence`` instance to Markdown.

    Args:
        evidence: The populated evidence model.

    Returns:
        A Markdown string ready to write to ``cra_evidence.md``.
    """
    lines: list[str] = []
    p = evidence.product

    lines.append("# CRA Evidence Pack")
    lines.append("")
    lines.append(f"**Regulation:** {evidence.regulation}  ")
    lines.append(f"**Article 14 applies from:** {evidence.art_14_applies_from}  ")
    lines.append(f"**Generated (UTC):** {evidence.generated_at_utc}  ")
    lines.append(f"**Tool:** {evidence.tool} v{evidence.tool_version}  ")
    lines.append("")

    # Product
    lines.append("## Product Identity")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Product ID | `{p.get('id', '')}` |")
    lines.append(f"| Name | {p.get('name', '')} |")
    lines.append(f"| Version | {p.get('version', '')} |")
    lines.append(f"| Manufacturer | {p.get('manufacturer', '')} |")
    if p.get("eu_representative"):
        lines.append(f"| EU Representative | {p['eu_representative']} |")
    if p.get("support_until"):
        lines.append(f"| Support Until | {p['support_until']} |")
    if p.get("annex_iii_classification"):
        lines.append(f"| Annex III Class | {p['annex_iii_classification']} |")
    if p.get("spoc_email"):
        lines.append(f"| SPOC Email | {p['spoc_email']} |")
    if p.get("cvd_policy_url"):
        lines.append(f"| CVD Policy | {p['cvd_policy_url']} |")
    lines.append("")

    # SBOM summary
    lines.append("## SBOM Inputs")
    lines.append("")
    for s in evidence.sbom_files:
        lines.append(
            f"- **{s.get('format', '')} {s.get('spec_version', '')}** — "
            f"{s.get('component_count', 0)} components, "
            f"{s.get('embedded_vuln_count', 0)} embedded vulnerabilities  "
        )
        if s.get("source_path"):
            lines.append(f"  Source: `{s['source_path']}`")
    lines.append("")

    # VEX summary
    if evidence.vex_files:
        lines.append("## VEX Summary")
        lines.append("")
        for v in evidence.vex_files:
            sc: dict[str, Any] = v.get("status_counts", {})
            lines.append(f"- Total statements: **{v.get('statement_count', 0)}**")
            lines.append(f"  - affected: {sc.get('affected', 0)}")
            lines.append(f"  - fixed: {sc.get('fixed', 0)}")
            lines.append(f"  - not_affected: {sc.get('not_affected', 0)}")
            lines.append(f"  - under_investigation: {sc.get('under_investigation', 0)}")
        lines.append("")

    # Findings
    lines.append("## Findings — CVE × Component Matrix")
    lines.append("")
    if not evidence.findings:
        lines.append("*No vulnerability findings detected in the provided SBOM/VEX inputs.*")
    else:
        lines.append(
            "| CVE | Component | VEX Status | Severity | CVSS | CRA Clauses |"
        )
        lines.append("|---|---|---|---|---|---|")
        for f in evidence.findings:
            comp = f.component_name or f.component_purl or "—"
            severity = f.severity or "—"
            cvss = str(f.cvss_score) if f.cvss_score is not None else "—"
            clause_titles = "; ".join(c["title"] for c in f.cra_clauses[:3])
            if len(f.cra_clauses) > 3:
                clause_titles += f" + {len(f.cra_clauses) - 3} more"
            lines.append(
                f"| {f.vulnerability_id} | {comp} | **{f.vex_status}** | "
                f"{severity} | {cvss} | {clause_titles} |"
            )
    lines.append("")

    # Art. 14 Notification Drafts
    if evidence.art14_notification_drafts:
        lines.append("## Art. 14 Notification Drafts")
        lines.append("")
        lines.append(
            "> These drafts are pre-filled with the data points the CRA requires. "
            "Review and submit to coordinator CSIRT + ENISA within 24h of discovery."
        )
        lines.append("")
        for i, draft in enumerate(evidence.art14_notification_drafts, 1):
            lines.append(f"### Draft {i}: {draft.vulnerability_id}")
            lines.append("")
            lines.append(f"- **Type:** {draft.notification_type}")
            lines.append(f"- **CRA Article:** {draft.cra_article}")
            lines.append(f"- **Product:** {draft.product_name} v{draft.product_version} (`{draft.product_id}`)")
            if draft.component_purl:
                lines.append(f"- **Component (purl):** `{draft.component_purl}`")
            if draft.cvss_score is not None:
                lines.append(f"- **CVSS Score:** {draft.cvss_score}")
            if draft.severity:
                lines.append(f"- **Severity:** {draft.severity}")
            lines.append(f"- **Exploitation flag:** {draft.exploitation_evidence_flag}")
            lines.append(f"- **Scope:** {draft.scope_note}")
            if draft.cra_article_verbatim:
                lines.append("- **Verbatim clause:**")
                lines.append(f"  > {draft.cra_article_verbatim[:400]}")
            lines.append("")

    # CRA Clauses Cited
    lines.append("## CRA Clauses Cited")
    lines.append("")
    lines.append(
        "All clause texts are verbatim from Regulation (EU) 2024/2847 (EUR-Lex). "
        "SHA-256 digests are computed over the UTF-8 text. "
        "Canonical source: https://eur-lex.europa.eu/eli/reg/2024/2847/oj"
    )
    lines.append("")
    for clause in evidence.cra_clauses_cited:
        lines.append(f"### {clause['title']}")
        lines.append("")
        lines.append(f"- **Key:** `{clause['key']}`")
        lines.append(f"- **Source:** {clause['source_url']}")
        lines.append(f"- **SHA-256 (text):** `{clause['sha256']}`")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*Generated by `cra-sbom-evidence`. This is engineering software, not legal advice. "
        "Regulatory submissions must be reviewed by qualified counsel.*"
    )
    lines.append("")

    return "\n".join(lines)
