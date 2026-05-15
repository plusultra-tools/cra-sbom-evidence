# cra-sbom-evidence

> CRA Article 14 evidence pack from your SBOM and VEX feeds. Every clause cited verbatim. Every output hashed. Vulnerability reporting becomes mandatory **2026-09-11** (CRA Art. 14(1)).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

`cra-sbom-evidence` (`cra-sbom` on the command line) is a focused CLI that takes a CycloneDX or SPDX SBOM and optional OpenVEX / CSAF VEX feeds, and produces a regulator-friendly CRA evidence pack: a JSON manifest with verbatim-cited CRA clauses, a human-readable Markdown report, a SHA-256 audit chain, and draft Art. 14 early-warning notifications pre-filled from your vulnerability data.

---

## Why this exists

The EU Cyber Resilience Act (Regulation (EU) 2024/2847, "CRA") enters its first binding phase on **11 September 2026** — Article 14's vulnerability reporting obligations. Manufacturers of products with digital elements ("PDEs") face fines up to **€15,000,000 or 2.5% of worldwide annual turnover** for non-compliance with Annex I and Articles 13-14 (CRA Art. 64(2)):

> "Non-compliance with the essential cybersecurity requirements set out in Annex I and the obligations set out in Articles 13 and 14 shall be subject to administrative fines of up to EUR 15 000 000 or, if the offender is an undertaking, up to 2,5 % of the its total worldwide annual turnover for the preceding financial year, whichever is higher."
> — CRA Art. 64(2), Regulation (EU) 2024/2847, OJEU 2024-11-20

Most existing SBOM tools (Syft, Trivy, cdxgen, Black Duck, Snyk) produce machine-readable inventories but **do not emit the regulatory evidence pack that a notified body or ENISA actually asks for**. This tool fills that gap: it quotes the regulation verbatim, maps every finding to the specific article or annex clause, and chains all outputs with SHA-256 so the evidence pack is tamper-evident the moment it leaves your pipeline.

**The single differentiator:** verbatim CRA clause citation + SHA-256 hash chain per clause. As of May 2026, none of the surveyed OSS tools (cyclonedx-cli, cdxgen, syft, trivy, sbomify) emit this. Commercial tools (craevidence.com, prismor.dev) reference articles by number but do not quote text.

---

## What it does

1. Ingests CycloneDX 1.4/1.5/1.6 and/or SPDX 2.3 JSON SBOMs.
2. Ingests OpenVEX 0.2.0+ and/or CSAF 2.0 VEX feeds (optional — falls back to CycloneDX embedded VEX).
3. Reads a product manifest YAML describing the manufacturer, support period, SPOC, and CVD policy.
4. Emits in `--out`:
   - `cra_evidence.json` — structured manifest with product identity, SBOM hashes, VEX disposition counts, every CVE × component pair with VEX status, and per-finding a verbatim CRA Article citation (Art. 11 vuln handling, Art. 14 reporting trigger conditions, Annex I essential cybersecurity requirements).
   - `cra_evidence.md` — human-readable rendering of (1).
   - `audit.sha256` — hash chain of all output files plus the inputs, tamper-evident.
   - Optionally: `notification_draft` entries embedded in `cra_evidence.json` for any high-severity affected component, pre-filled per Art. 14(2)(a).

---

## Install

```bash
pip install cra-sbom-evidence
```

Or from source:

```bash
git clone https://github.com/plusultra/cra-sbom-evidence
cd cra-sbom-evidence
pip install -e .
```

Requires Python 3.10+, pydantic ≥ 2.0, pyyaml ≥ 6.0. No GPU, no network calls at runtime.

---

## Quickstart

```bash
cra-sbom evidence \
  --sbom sbom.json \
  --vex vex.json \
  --product product.yaml \
  --out out/
```

See `examples/quickstart/` for sample inputs that run out of the box.

### Verify the evidence pack

```bash
cra-sbom verify --evidence-pack out/
```

### Verify that bundled CRA clause texts have not drifted

```bash
cra-sbom verify-citations
```

---

## Output structure

```
out/
├── cra_evidence.json   — machine-readable manifest (sorted keys, deterministic)
├── cra_evidence.md     — human-readable Markdown report
└── audit.sha256        — tamper-evident hash chain over all inputs + outputs
```

### cra_evidence.json schema (key fields)

```json
{
  "tool": "cra-sbom-evidence",
  "tool_version": "0.1.0",
  "regulation": "Regulation (EU) 2024/2847",
  "art_14_applies_from": "2026-09-11",
  "product": { "id": "...", "name": "...", "manufacturer": "...", ... },
  "sbom_files": [ { "format": "CycloneDX", "spec_version": "1.5", ... } ],
  "findings": [
    {
      "vulnerability_id": "CVE-2024-XXXX",
      "component_name": "openssl",
      "vex_status": "not_affected",
      "cra_clauses": [
        {
          "key": "art_14_1",
          "title": "Article 14(1) — Notification of actively exploited vulnerabilities",
          "text_excerpt": "A manufacturer shall notify any actively exploited vulnerability...",
          "sha256": "..."
        }
      ]
    }
  ],
  "art14_notification_drafts": [ ... ],
  "cra_clauses_cited": [ ... ]
}
```

---

## Product manifest YAML

```yaml
id: "my-product-v1.2.3"
name: "My Product"
version: "1.2.3"
manufacturer: "Acme GmbH"
eu_representative: "Acme EU Rep, Berlin, DE"
intended_use: "Industrial IoT gateway"
support_until: "2031-06-18"
annex_iii_classification: "Class I — routers/modems (Annex III §12)"
spoc_email: "psirt@acme.example"
spoc_url: "https://acme.example/security"
cvd_policy_url: "https://acme.example/security/cvd-policy"
```

---

## What this tool does NOT cover (honest gap list)

- **ENISA Single Reporting Platform direct submission.** The Art. 14 notification drafts in `cra_evidence.json` are pre-filled templates; you must submit them to the ENISA SRP endpoint under your own manufacturer credentials. The SRP API spec is still in beta (May 2026); we will add a direct-submit flag when the spec stabilises.
- **Supply-chain attestation / sigstore cosign.** The audit chain is a local SHA-256 file. SBOM signing with sigstore / cosign is out of scope for v0.1.
- **BSI TR-03183-2 compliance scoring.** The 10 mandatory SBOM fields per BSI TR-03183-2 are referenced in Annex I Part II but this tool does not score or warn on missing fields. `sbomqs` can fill that gap.
- **Annex VII technical documentation.** Art. 31 requires a full technical dossier. This tool generates the SBOM/VEX evidence section; the rest of Annex VII (design decisions, risk assessment, test results) is out of scope.
- **Conformity assessment.** Conformity assessment per Art. 32 is done by your notified body or under Module A internal control. This tool helps you prepare the evidence; it does not certify compliance.
- **AI Act, MDR/IVDR, NIS2.** Sibling tools: `fmm-fairness-eval` (AI Act Art. 10), `dcm-anon` (GDPR/HIPAA).

---

## CRA citations used in output (verbatim from OJEU 2024-11-20)

All verbatim clause texts are from Regulation (EU) 2024/2847 as published in the Official Journal of the European Union on 2024-11-20. Canonical EUR-Lex URL: https://eur-lex.europa.eu/eli/reg/2024/2847/oj

**Article 14(1):** "A manufacturer shall notify any actively exploited vulnerability contained in the product with digital elements that it becomes aware of simultaneously to the CSIRT designated as coordinator, in accordance with paragraph 7 of this Article, and to ENISA."

**Article 64(2):** "Non-compliance with the essential cybersecurity requirements set out in Annex I and the obligations set out in Articles 13 and 14 shall be subject to administrative fines of up to EUR 15 000 000 or, if the offender is an undertaking, up to 2,5 % of the its total worldwide annual turnover for the preceding financial year, whichever is higher."

**Article 71(2):** "This Regulation shall apply from 11 December 2027. However, Article 14 shall apply from 11 September 2026 and Chapter IV (Articles 35 to 51) shall apply from 11 June 2026."

**Annex I Part II point (1):** "identify and document vulnerabilities and components contained in products with digital elements, including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies of the products"

Full clause texts with SHA-256 digests are bundled in `src/cra_sbom_evidence/data/cra_clauses.yaml` and verified at runtime by `cra-sbom verify-citations`.

See `docs/cra-citation-map.md` for the full clause-to-finding mapping table.

---

## License

MIT. See [LICENSE](LICENSE).

This is engineering software. Not legal advice. Regulatory submissions must be reviewed by qualified counsel before submission to the coordinator CSIRT and ENISA.

---

## Contributing

Issues and pull requests welcome. Before submitting code: run `python -m pytest`, `python -m ruff check src tests`, `python -m mypy --strict src`. See `SECURITY.md` for vulnerability reporting.

---

## See also

- ENISA CRA hub: https://www.enisa.europa.eu/topics/cra
- ENISA Security-by-Design Playbook (2026-03-19)
- OpenSSF CRA Brief Guide for OSS Developers: https://best.openssf.org/CRA-Brief-Guide-for-OSS-Developers.html
- BSI TR-03183-2 (10 mandatory SBOM fields): https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2.html
- CycloneDX 1.5 spec: https://cyclonedx.org/docs/1.5/json/
- OpenVEX spec: https://github.com/openvex/spec
- CSAF 2.0 spec: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
- awesome-cra-compliance: https://github.com/cra-compliance-lab/awesome-cra-compliance
