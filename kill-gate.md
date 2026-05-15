# Kill-gate — cra-sbom-evidence

**Set:** 2026-05-15.
**Day-0 = day of GitHub release / PyPI publication.**
**Decision day = Day-30 (target: 2026-07-15 if launched 2026-06-15).**
**Secondary gate at d+60 for paid pilots.**

Context: CRA Article 14 reporting obligations take effect **2026-09-11** (87 days from 2026-06-15). Buyers face hard deadline + €15M fine exposure. Kill-gate is set tighter than fmm-fairness-eval because the forcing function is externally mandated and dated.

---

## Pass conditions (any ONE = continue to Phase 2)

| Metric | Threshold | How measured | Rationale |
|---|---|---|---|
| GitHub stars | ≥ 30 by d+30 | Public counter | Lower than CRA recon forecast (≥150) because we are launching earlier; re-calibrate at d+14 |
| `pip install cra-sbom-evidence` last_week | ≥ 10 by d+30 | https://pypistats.org | Real adoption signal |
| Real-affiliation issues (employer link in profile) | ≥ 2 by d+30 | GitHub issue tracker | Strongest demand signal — someone with skin-in-game filed it |
| Commercial inbound (email/DM from company) | ≥ 1 by d+30 | plusultra.dev@proton.me mailbox | Willingness-to-pay signal |
| Paid pilot (€49/mo) | ≥ 1 by d+60 | Stripe or direct invoice | Revenue signal; hard deadline creates urgency |
| ENISA / EU cluster acknowledgement | ≥ 1 by d+60 | OpenSSF list, OSCRAT, CRACoWi, STAN4CRA | Regulatory credibility moat |

**Hit any one = green.** Proceed to Phase 2.

---

## Fail conditions (ALL of the below = kill)

- < 10 stars by d+30
- 0 real-affiliation issues by d+30
- 0 commercial inbound by d+30
- 0 paid pilots by d+60

If all hit: archive repo (retain code for portfolio — it demonstrates CRA/SBOM domain knowledge), write post-mortem in `archive/`, pivot focus.

**Day-14 mini-gate (NEW):** by d+14, if 0 commercial inbound AND 0 real-affiliation issues, run `/structured-redteam cra-sbom-evidence` adversarial review against v0.1 positioning. Cheap, no-spend, reorients or confirms.

---

## Yellow zone behaviour

1–2 metrics near (>50% of) threshold, others below:
1. Publish one technical post on dev.to/HN (no spend): "What CRA Art. 14 actually requires your SBOM to prove (with code)".
2. File a PR on awesome-cra-compliance + awesome-sbom.
3. Post to openssf-sig-cra-standards mailing list (5 members, high signal).
4. Wait additional 15d. Re-evaluate at d+45.

If still yellow at d+45: fold unless ≥1 commercial inbound with real budget signal.

---

## Phase 2 conditions (on green pass)

1. Stand up hosted CI signing service: Stripe €49/mo (SMB, one product) / €99/mo (Pro, Slack/Teams Art. 14 notification trigger). Target d+30 from green.
2. Implement direct ENISA SRP API submission when the SRP spec is finalised (estimated Q4 2026).
3. Build CSAF 2.0 export flag (`cra-sbom evidence --output-csaf`) for ENISA machine-readable channel.
4. Publish OSF/arxiv preprint: "Verbatim-cited CRA Article 14 evidence generation from SBOM + VEX feeds" — establishes first-mover citation priority.
5. Submit to CycloneDX Tool Center and awesome-cra-compliance on day-1 post-launch.
