# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-05 16:19:18Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-04`
- **Included count:** 6

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-18658 | Core enterprise decision engine (BRMS) underpinning regulated Finance (fraud/credit) and Government (benefits/compliance) workflows, with unauthenticated RCE risk. | IBM’s Operational Decision Manager faces a critical unauthenticated SQLi-to-RCE flaw (CVE-2026-18658), threatening the backend rule engines that power financial fraud detection and government benefit systems. With no workarounds available, regulated sectors must prioritize patching and network segmentation immediately. |
| 4 | 2 | CVE-2026-61686 | Finance sector relevance: open-source invoicing platform handling billing, payment tracking, and client financial data with potential RCE via authenticated deserialization. | TIER 2 alert for financial operations: CVE-2026-61686 exposes SolidInvoice to authenticated PHP object injection, risking RCE and financial data exposure. While credentials are required, the potential for server compromise underscores the need to patch invoicing platforms handling sensitive billing workflows. |
| 4 | 2 | CVE-2026-85184 | Critical authentication bypass in a foundational Node.js web framework plugin, impacting General Infrastructure and Digital Identity controls for public-facing APIs and regulated services. | A TIER 2 critical flaw in @fastify/middie allows unauthenticated attackers to bypass path-scoped auth controls via absolute-form URIs. Teams running Fastify-based public APIs or regulated services should patch immediately or refactor to preHandler hooks. |
| 4 | 2 | CVE-2026-85398 | Direct Healthcare sector impact via unauthenticated SQLi in a Hospital Information System, risking patient data breaches and regulatory compliance failures. | Hospital Information Systems face critical SQL injection risks that can expose sensitive patient records. Even on internal networks, unauthenticated access points demand immediate WAF rules and network segmentation to protect healthcare data. |
| 4 | 2 | CVE-2026-85689 | SQLi in enterprise RAG framework threatens financial contract data and government compliance workflows, bypassing internal data scoping controls. | A TIER 2 SQL injection in a popular enterprise RAG framework exposes sensitive financial and government documents to cross-collection data breaches. Organizations deploying AI pipelines for compliance and contract analysis must patch immediately and enforce strict API input validation. |
| 2 | 2 | CVE-2026-18221 | Tier 2 remote authentication bypass in IBM i mainframe OS, a foundational enterprise stack widely deployed in regulated finance and government environments. | IBM i environments face a high-severity remote authentication bypass with no vendor workarounds. While typically internal, this Tier 2 flaw underscores the need for strict network segmentation and rapid patching in regulated enterprise and public-sector mainframe deployments. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-18175.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19283.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53603.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53604.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61699.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75925.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78327.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81665.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85397.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85504.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85507.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85525.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85533.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85546.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85594.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85613.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85616.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85617.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85620.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85624.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85654.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85664.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85668.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85700.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86098.md` — heuristic TIER 3/4
