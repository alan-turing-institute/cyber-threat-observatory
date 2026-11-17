# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-17 08:02:42Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-16`
- **Included count:** 5

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-130070 | Critical unauthenticated authentication bypass and OAuth token theft in a Frappe/ERPNext extension, directly impacting Digital Identity pipelines and public service account security. | A critical TIER 2 flaw in a popular Frappe/ERPNext module allows attackers to bypass OTP and steal OAuth tokens for arbitrary accounts. For DPI operators relying on digital identity conversion pipelines, this unauthenticated account takeover risk demands immediate patching. |
| 4 | 2 | CVE-2026-104840 | Critical for Government/CERT infrastructure; unauthenticated brute-force on OpenCTI threatens national threat intelligence platforms and defence agency data. | National CERTs and defence agencies relying on OpenCTI must patch immediately: a missing rate limit allows unauthenticated brute-force attacks at network speed, risking full compromise of sensitive threat intelligence hubs. |
| 4 | 2 | CVE-2026-127218 | Unauthenticated DoS in Axigen Mail Server, a foundational email gateway explicitly tied to government, finance, and healthcare communications infrastructure. | Enterprise email gateways like Axigen are critical to government and regulated sector communications. This unauthenticated DoS flaw can crash entire mail services with a single request, highlighting the need for strict WAF controls and prompt patching in public-facing infrastructure. |
| 3 | 2 | CVE-2026-129295 | General infrastructure email parsing library underpins critical ticketing and quarantine operations across Finance, Government, and Healthcare sectors. | A trivial ReDoS in a common Python email parser can stall backend workers for hours, disrupting critical ticketing and quarantine systems in regulated sectors. Patching or enforcing header limits is essential for DPI resilience. |
| 3 | 2 | CVE-2026-130066 | Tier 2 authenticated SQLi in widely deployed enterprise groupware (SOGo) that leaks password hashes, impacting public sector, healthcare, and finance deployments. | Public-facing groupware servers like SOGo are prime targets for credential harvesting. This Tier 2 SQLi highlights the need for strict patching and MFA in regulated environments where webmail bridges internal and external access. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-5809.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111760.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120697.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129854.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129872.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130073.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130074.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18564.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19732.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63477.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76823.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77033.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82156.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95839.md` — heuristic TIER 3/4
