# PSIRT process — Product Security Incident Response

> Template to satisfy CRA Annex I Part II points (5) and (6), Article 13(17),
> and Article 15. Customise the **{{PLACEHOLDERS}}** for your organisation
> before publication.

## 1. Scope

This document defines the **Product Security Incident Response Team (PSIRT)**
process for **{{PRODUCT_NAME}}** (manufacturer: **{{MANUFACTURER_LEGAL_NAME}}**).
It applies for the entire **support period** declared in the compliance
manifest (**{{SUPPORT_PERIOD_START}}** → **{{SUPPORT_PERIOD_END}}**).

## 2. Single point of contact (Art. 13(17))

- Email: **{{SPOC_EMAIL}}**
- Web form: **{{SPOC_URL}}**
- PGP key fingerprint: **{{SPOC_PGP_FINGERPRINT}}**
- Languages: English; **{{ADDITIONAL_LANGUAGES}}**.
- SLA for first acknowledgement: **24 hours** (business and non-business days).

## 3. Coordinated vulnerability disclosure policy (Annex I Part II.5)

Public URL: **{{CVD_POLICY_URL}}**.

Terms (default):
1. Reporters may submit anonymously or with credit.
2. Default embargo: **90 days** from confirmed reproduction. Reporter may
   propose a longer or shorter window.
3. We will request a CVE through MITRE within 14 days of triage.
4. We will not pursue legal action against good-faith researchers acting
   within the scope of this policy.

## 4. Roles

| Role | Responsibility | Owner |
|---|---|---|
| PSIRT Lead | Triage, communication | **{{PSIRT_LEAD}}** |
| Maintainer on call | Fix authoring | rotation |
| Release engineer | Signed update build + dissemination | **{{RELEASE_ENG}}** |
| Communications | Advisory copy + customer notice | **{{COMMS_OWNER}}** |
| Legal | Art. 14 reporting decision | **{{LEGAL_OWNER}}** |

## 5. Triage matrix

| Discovered | Action | Deadline |
|---|---|---|
| Actively exploited | Art. 14(1) early warning to CSIRT + ENISA | **24h** |
| Confirmed vulnerability | Art. 14(2) notification with corrective measures | **72h** |
| Fix available | Art. 14(3) final report; public advisory | **14 days** |
| Severe incident | Art. 14(3) + 1-month threat analysis | **1 month** |
| Voluntary report (no obligation) | Art. 15(1) submission | best effort |

## 6. Reporting channels (Art. 14)

- **Coordinator CSIRT (Member State of registered establishment)**:
  **{{NATIONAL_CSIRT_ENDPOINT}}**
- **ENISA Single Reporting Platform**: **{{ENISA_SRP_ENDPOINT}}**
- All notifications are also archived under
  `evidence-pack/audit.json` for the 10-year retention required by
  Art. 13(13).

## 7. Update dissemination (Annex I Part II.7 / II.8)

- Signed updates only (Ed25519 / X.509).
- Signing key fingerprint: **{{UPDATE_SIGNING_KEY}}**.
- Distribution channel: **{{UPDATE_CHANNEL}}**.
- Free of charge unless covered by a tailor-made business contract per
  Annex I Part II point (8).
- Retention: each update remains available **10 years** post-issuance
  (Art. 13(9)).

## 8. SBOM and VEX publication

- SBOM (CycloneDX 1.5): **{{SBOM_URL}}**
- VEX (OpenVEX or CSAF 2.0): **{{VEX_URL}}**
- Updated within **5 working days** of every release; per-vulnerability VEX
  statements updated within **72 hours** of triage.

## 9. Annual review

Reviewed annually; next review date: **{{NEXT_REVIEW_DATE}}**. Changes
appended to the audit log with the signed hash chain in
`evidence-pack/audit.json`.
