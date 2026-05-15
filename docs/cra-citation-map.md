# CRA clause-to-finding citation map

This table maps finding types produced by `cra-sbom-evidence` to the specific CRA article or annex clause they evidence. Left column: verbatim text excerpt. Right column: citation and key.

Source: Regulation (EU) 2024/2847, OJEU 2024-11-20.
Canonical URL: https://eur-lex.europa.eu/eli/reg/2024/2847/oj

---

## 1. SBOM existence and format

| Verbatim excerpt | Citation |
|---|---|
| "identify and document vulnerabilities and components contained in products with digital elements, including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies of the products" | Annex I Part II point (1) — key: `annex_i_part_ii` |
| "The Commission may, by means of implementing acts taking into account European or international standards and best practices, specify the format and elements of the software bill of materials referred to in Part II, point (1), of Annex I." | Art. 13(24) — key: `art_13_24` |

---

## 2. Manufacturer obligations — component due diligence

| Verbatim excerpt | Citation |
|---|---|
| "When placing a product with digital elements on the market, manufacturers shall ensure that it has been designed, developed and produced in accordance with the essential cybersecurity requirements set out in Part I of Annex I." | Art. 13(1) — key: `art_13_1` |
| "For the purpose of complying with paragraph 1, manufacturers shall exercise due diligence when integrating components sourced from third parties so that those components do not compromise the cybersecurity of the product with digital elements, including when integrating components of free and open-source software that have not been made available on the market in the course of a commercial activity." | Art. 13(5) — key: `art_13_5` |
| "Manufacturers shall, upon identifying a vulnerability in a component, including in an open source-component, which is integrated in the product with digital elements report the vulnerability to the person or entity manufacturing or maintaining the component, and address and remediate the vulnerability in accordance with the vulnerability handling requirements set out in Part II of Annex I." | Art. 13(6) — key: `art_13_6` |
| "Manufacturers shall ensure, when placing a product with digital elements on the market, and for the support period, that vulnerabilities of that product, including its components, are handled effectively and in accordance with the essential cybersecurity requirements set out in Part II of Annex I." | Art. 13(8) — key: `art_13_8` |

---

## 3. Vulnerability handling (all findings)

| Finding type | Verbatim excerpt | Citation |
|---|---|---|
| Any finding | Annex I Part II points (1)-(8) — SBOM, patch, test, disclosure, CVD, update dissemination | Annex I Part II — key: `annex_i_part_ii` |
| Affected / under_investigation | "Manufacturers shall, upon identifying a vulnerability..." | Art. 13(6) — key: `art_13_6` |
| High-severity affected | See Art. 14(1) below | Art. 14(1) — key: `art_14_1` |

---

## 4. Art. 14 notification triggers

| Finding type | Verbatim excerpt | Citation |
|---|---|---|
| Actively exploited vulnerability (CVSS ≥ 7.0, status=affected) | "A manufacturer shall notify any actively exploited vulnerability contained in the product with digital elements that it becomes aware of simultaneously to the CSIRT designated as coordinator, in accordance with paragraph 7 of this Article, and to ENISA." | Art. 14(1) — key: `art_14_1` |
| 24h / 72h / 14d timeline | "Manufacturers must submit: (a) early warning notification within 24 hours; (b) vulnerability notification within 72 hours with general information about the product, exploit nature, and corrective measures; (c) final report within 14 days..." | Art. 14(2) — key: `art_14_2` |
| Severe incident | "A manufacturer shall notify any severe incident having an impact on the security of the product with digital elements that it becomes aware of simultaneously to the CSIRT designated as coordinator, in accordance with paragraph 7 of this Article, and to ENISA." | Art. 14(3) — key: `art_14_3` |
| Voluntary report | "Manufacturers as well as other natural or legal persons may notify any vulnerability contained in a product with digital elements as well as cyber threats that could affect the risk profile of a product with digital elements on a voluntary basis to a CSIRT designated as coordinator or ENISA." | Art. 15(1) — key: `art_15_1` |

---

## 5. Penalties / consequence mapping

| Finding type | Verbatim excerpt | Citation |
|---|---|---|
| Annex I + Art. 13 + Art. 14 non-compliance | "Non-compliance with the essential cybersecurity requirements set out in Annex I and the obligations set out in Articles 13 and 14 shall be subject to administrative fines of up to EUR 15 000 000 or, if the offender is an undertaking, up to 2,5 % of the its total worldwide annual turnover for the preceding financial year, whichever is higher." | Art. 64(2) — key: `art_64_2` |

---

## 6. Dates

| Event | Verbatim excerpt | Citation |
|---|---|---|
| Art. 14 applies | "This Regulation shall apply from 11 December 2027. However, Article 14 shall apply from 11 September 2026..." | Art. 71(2) — key: `art_71_2` |

---

## 7. Essential cybersecurity requirements (Annex I Part I)

Finding type: product design / architecture requirements evidenced by SBOM metadata and product manifest.

| Req. # | Summary | Verbatim (partial) |
|---|---|---|
| 1 | No known exploitable vulnerabilities at market placement | "be made available on the market without known exploitable vulnerabilities" |
| 2 | Secure by default | "be made available on the market with a secure by default configuration" |
| 3 | Security update mechanism | "ensure that vulnerabilities can be addressed through security updates..." |
| 4 | Authentication / access control | "ensure protection from unauthorised access by appropriate control mechanisms..." |
| 5 | Confidentiality (encryption) | "protect the confidentiality of stored, transmitted or otherwise processed data..." |
| 6 | Integrity | "protect the integrity of stored, transmitted or otherwise processed data..." |
| 7 | Data minimisation | "process only data, personal or other, that are adequate, relevant and limited to what is necessary..." |
| 8 | Availability / DoS resilience | "protect the availability of essential and basic functions, also after an incident..." |
| 9 | Attack-surface reduction | "be designed, developed and produced to limit attack surfaces, including external interfaces" |
| 10 | Exploitation mitigation | "be designed, developed and produced to reduce the impact of an incident using appropriate exploitation mitigation mechanisms" |
| 11 | Security monitoring / logging | "provide security related information by recording and monitoring relevant internal activity..." |
| 12 | Secure deletion | implied in Part I final item |

Full text in `data/cra_clauses.yaml`, key: `annex_i_part_i`.
