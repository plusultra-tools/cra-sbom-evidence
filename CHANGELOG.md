# Changelog

All notable changes to this project will be documented here.

## v0.1.0 — 2026-05-15 (initial release)

- CLI `cra-sbom evidence` generates CRA Article 14 evidence packs from CycloneDX 1.4/1.5/1.6 and SPDX 2.3 JSON SBOMs.
- Parses OpenVEX 0.2.0+ and CSAF 2.0 VEX feeds; falls back to CycloneDX embedded VEX analysis.
- Emits `cra_evidence.json` with verbatim-cited CRA clause texts (Art. 13, Art. 14, Art. 15, Art. 31, Art. 32, Art. 64, Art. 71, Annex I Part I + II, Annex III Class I + II).
- Emits `cra_evidence.md` (human-readable) and `audit.sha256` (tamper-evident SHA-256 chain).
- Generates Art. 14(2)(a) early-warning notification drafts for high-severity (CVSS ≥ 7.0) affected components.
- `cra-sbom verify` validates the audit chain of a previously generated pack.
- `cra-sbom verify-citations` recomputes SHA-256 of bundled clause texts and asserts identity.
- 72 pytest test cases passing under Python 3.10–3.14.
- ruff + mypy --strict clean.
- 23 CRA clauses bundled with SHA-256 integrity hashes in `data/cra_clauses.yaml`.
- PSIRT process template and 24h Art. 14 early-warning notice template in `templates/`.

## Roadmap (v0.2 candidates, dependent on signal)

- Direct ENISA Single Reporting Platform API submission (once ENISA SRP spec is finalised).
- BSI TR-03183-2 compliance scorer (10 mandatory SBOM fields).
- Annex VII technical documentation scaffold generator.
- CSAF 2.0 VEX export from `cra_evidence.json` for SRP machine-readable channel.
- Hosted CI signing service (€49-99/mo) — gated on kill-gate validation pass (d+30).
