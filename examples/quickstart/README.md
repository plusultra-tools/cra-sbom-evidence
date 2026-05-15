# Quickstart example

This directory contains minimal sample inputs to try `cra-sbom-evidence` immediately.

## Files

- `sbom.json` — CycloneDX 1.5 SBOM with 2 components (`openssl`, `libexpat`) and 2 embedded vulnerabilities (one not_affected, one exploitable/critical).
- `vex.json` — OpenVEX 0.2.0 feed overriding those two vulnerabilities with explicit dispositions.
- `product.yaml` — Product manifest for a fictional "My Product v1.2.3".

## Run it

```bash
pip install cra-sbom-evidence

cra-sbom evidence \
  --sbom sbom.json \
  --vex vex.json \
  --product product.yaml \
  --out out/
```

## Expected output

```
OK: evidence pack written to out/
  cra_evidence.json  (sha256 prefix=...)
  cra_evidence.md    (sha256 prefix=...)
  audit.sha256       (chain sha256=...)
Findings: 2
Art. 14 drafts: 1
CRA clauses cited: 7
```

The Art. 14 draft is triggered for `CVE-2024-0002` (CVSS 9.1, critical, affected) and pre-filled with the product identity, component purl, and verbatim Art. 14(1) clause text.

## Verify the pack

```bash
cra-sbom verify --evidence-pack out/
# OK: audit chain verified — all hashes match.

cra-sbom verify-citations
# OK: all 23 clause texts match their stored SHA-256 digests.
```

## What the evidence JSON contains

```json
{
  "tool": "cra-sbom-evidence",
  "regulation": "Regulation (EU) 2024/2847",
  "art_14_applies_from": "2026-09-11",
  "product": {
    "id": "my-product-v1.2.3",
    "name": "My Product",
    "manufacturer": "Example Corp",
    ...
  },
  "findings": [
    {
      "vulnerability_id": "CVE-2024-0001",
      "component_name": "openssl",
      "vex_status": "not_affected",
      "cra_clauses": [ { "key": "art_13_6", "title": "...", "text_excerpt": "...", "sha256": "..." } ]
    },
    {
      "vulnerability_id": "CVE-2024-0002",
      "component_name": "libexpat",
      "vex_status": "affected",
      "cvss_score": 9.1,
      "severity": "critical",
      "cra_clauses": [ ... ]
    }
  ],
  "art14_notification_drafts": [
    {
      "vulnerability_id": "CVE-2024-0002",
      "cra_article": "Article 14(1) and 14(2)(a)",
      "cra_article_verbatim": "A manufacturer shall notify any actively exploited vulnerability...",
      ...
    }
  ]
}
```
