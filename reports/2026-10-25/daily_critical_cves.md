# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-26 03:51:46Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-25`
- **Included count:** 2

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-116000 | TIER 2 SSRF/path traversal in on-premise AI RAG framework explicitly deployed in Finance, Healthcare, and Government for sensitive document processing. | Unauthenticated SSRF in PrivateGPT enables arbitrary file reads on internal AI servers. Critical for regulated sectors deploying on-premise RAG to process sensitive financial, health, or government data—enforce network segmentation and API auth now. |
| 4 | 2 | CVE-2026-116006 | Direct authentication bypass in a widely deployed enterprise/public-sector backend framework, compromising SMS verification and token issuance for full admin takeover. | A hardcoded SMS code in a popular enterprise admin framework turns internal authentication into a trivial bypass, highlighting how default configurations can undermine digital identity systems in public and regulated sectors. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-116068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116175.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116189.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116194.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116200.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116201.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-116173.md` — heuristic TIER 3/4
