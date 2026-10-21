# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-21 20:50:05Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-19`
- **Included count:** 5

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2025-10149 | Directly impacts core Digital Identity infrastructure (WSO2 Identity Server) via SCIM authorization bypass enabling federated-to-local account takeover. | Identity providers are the backbone of digital public infrastructure. CVE-2025-10149 highlights a critical SCIM flaw in WSO2 Identity Server that allows authenticated federated users to hijack local accounts, underscoring the need for strict IdP hardening and username collision policies. |
| 4 | 2 | CVE-2026-112252 | Targets government safety bureaus and state-owned enterprises via a critical infrastructure compliance system, enabling unauthenticated RCE on internal regulatory networks. | A TIER 2 SQLi in a Chinese government safety compliance system highlights how internal regulatory platforms can become high-value targets for APTs. With a ready-to-use PoC and RCE potential, public-sector infrastructure must enforce strict network segmentation and disable legacy SQL features like xp_cmdshell. |
| 4 | 2 | CVE-2026-13695 | Unauthenticated SQLi on an enterprise HR login endpoint enables credential theft and PII exposure, directly impacting Digital Identity and Government/Finance workforce systems. | Enterprise HR platforms serve as critical identity gateways for public and regulated sectors. This unauthenticated SQLi on the login endpoint underscores why network segmentation and strict access controls remain essential for protecting workforce credentials and payroll data. |
| 4 | 2 | CVE-2026-78164 | Foundational enterprise middleware (Apache Camel) widely deployed in finance, healthcare, and government API routing; default-vulnerable secret/env-var leakage poses direct credential harvesting risk to regulated integrations. | Apache Camel’s default-vulnerable placeholder injection (CVE-2026-78164) can silently leak cloud vault secrets and environment variables from internal API gateways. Finance, healthcare, and government teams relying on Camel for data orchestration should patch immediately or strip control headers at trust boundaries. |
| 4 | 2 | CVE-2026-85251 | Foundational enterprise middleware handling OAuth2 tokens and credentials; redirect-based leakage risks identity, finance, and government integration flows. | Enterprise integration frameworks like Apache Camel quietly power digital identity and financial API exchanges. A redirect flaw leaking OAuth2 tokens highlights why middleware security must match endpoint rigor. Patch or disable auto-redirects on credentialed routes. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-103314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107366.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10743.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107571.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111440.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111441.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112188.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112264.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112265.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112366.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112368.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112406.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12148.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12665.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79983.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79984.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79986.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83531.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90910.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-112377.md` — heuristic TIER 3/4
