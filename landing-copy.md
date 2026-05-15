# Landing copy — cra-sbom-evidence

For future Carrd / static landing page.

---

## Hero

**Your SBOM already has the evidence. This tool surfaces it — verbatim-cited, hash-chained, Art. 14-ready.**

CRA Article 14 vulnerability reporting becomes mandatory on **11 September 2026**. `cra-sbom-evidence` turns your existing CycloneDX or SPDX SBOM into a regulator-ready evidence pack in under 30 seconds. Every CRA clause quoted verbatim. Every output tamper-evident.

[GitHub](https://github.com/plusultra/cra-sbom-evidence) — [PyPI](https://pypi.org/project/cra-sbom-evidence/) — [docs](https://github.com/plusultra/cra-sbom-evidence#readme)

---

## What it does

Feed it your SBOM + VEX + product manifest. Get a complete CRA Art. 14 evidence pack out:

- Every CVE × component pair cross-referenced to the specific CRA article or Annex clause.
- Verbatim clause text, not paraphrase — so your notified body can verify it themselves.
- SHA-256 audit chain over all inputs and outputs — tamper-evident from the moment it leaves your pipeline.
- Art. 14(1)/(2) early-warning notification drafts pre-filled from your vulnerability data.
- `verify-citations` command that recomputes clause hashes at any time — regulatory drift = test failure.

---

## For who

- **Embedded firmware teams** shipping IoT devices, routers, smart-home hardware — Annex III Class I manufacturers.
- **EU SaaS companies** in NIS2 scope that also ship software products (CRA applies when you ship code as a product, not just a service).
- **PSIRTs** who need a structured, traceable Art. 14 notification workflow.
- **Compliance engineers** preparing the Annex VII technical dossier — this generates the SBOM/VEX section.
- **DevSecOps engineers** integrating SBOM generation into CI/CD — `cra-sbom evidence` is a one-command step.

---

## Why not just use sbomify / Trivy / cdxgen?

All of them produce SBOMs. None of them (as of May 2026) emit:
1. Verbatim CRA clause text mapped to each finding.
2. A SHA-256 hash chain over the evidence pack.
3. Art. 14 notification drafts pre-filled from VEX data.

`cra-sbom-evidence` is not a replacement for those tools — it consumes their SBOM output and adds the regulatory evidence layer on top.

---

## Pricing

- **OSS CLI** — MIT, always free. `pip install cra-sbom-evidence`.
- **Hosted CI (Phase 2, not yet shipped)** — every SBOM push triggers an evidence pack + audit report in CI, retained with a permanent audit log. €49/mo SMB (1 product) / €99/mo Pro (3 products + Slack/Teams Art. 14 trigger). Reserve access below.
- **Consulting** — CRA Art. 14 compliance workflow design for your PSIRT / DevSecOps team. Email `plusultra.dev@proton.me`.

---

## Reserve early access to hosted CI

(Email form embed — collects email + role + organisation. No tracking.)

---

## The deadline

**87 days.** That is how long you have from today (2026-06-15) to get Art. 14 reporting operational before the deadline (2026-09-11). A non-trivial percentage of the 29,500+ NIS2-scoped EU companies ship software products. Most don't have a PSIRT workflow yet. This tool is the fastest path to an auditable Art. 14 evidence trail.
