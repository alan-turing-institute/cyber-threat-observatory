# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-27 11:32:26Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-26`
- **Included count:** 4

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-100612 | Digital Identity sector: directly compromises SSO trust anchors and identity federation in enterprise IdAM stacks, enabling vertical privilege escalation to full org owner control. | A flawed database migration in Capgo’s platform lets compromised admins hijack SSO trust anchors and take over org owner accounts. For DPI and enterprise identity teams, this underscores the critical need to harden IdP configurations and enforce column-level security on federation metadata. |
| 4 | 2 | CVE-2026-100661 | Foundational Java networking library (Netty) underpinning public-facing API gateways and microservices across Finance, Government, and Healthcare, with unauthenticated DoS risk in default HTTP/3 configurations. | Netty’s HTTP/3 decoder flaw exposes a silent DoS risk for public-facing Java services. With zero configuration barriers and no WAF workaround, regulated sectors relying on Netty for API gateways and microservices must patch immediately to avoid event-loop starvation and heap exhaustion. |
| 4 | 2 | CVE-2026-100666 | Core Java networking library (Netty) underpins public-facing APIs and microservices across finance, healthcare, and government sectors. | Netty's widespread use in Java-based public services makes this HTTP desync flaw a priority for DPI operators, despite requiring specific client-side conditions. Patch or disable pipelining at the edge. |
| 3 | 2 | CVE-2026-100662 | Foundational Java networking library (Netty) underpins public-facing APIs and edge proxies; unauthenticated HTTP/3 DoS threatens availability of regulated and civic digital services. | A TIER 2 vulnerability in Netty’s HTTP/3 stack enables unauthenticated memory exhaustion attacks against default Java web servers and edge proxies. With a ready-to-use PoC and no safe workarounds, DPI operators must patch to 4.2.18.Final to safeguard critical internet-facing infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-100520.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100578.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100582.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100586.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100588.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100594.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100595.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100597.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100598.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100599.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100632.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100665.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100683.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100685.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100686.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100690.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100703.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72668.md` — heuristic TIER 3/4
