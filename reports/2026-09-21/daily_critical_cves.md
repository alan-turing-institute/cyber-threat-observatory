# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-22 15:02:45Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-21`
- **Included count:** 4

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-77560 | TIER 2 authorization bypass in Tinyauth forward-auth middleware directly impacts Digital Identity infrastructure by allowing authenticated users to bypass per-app access controls via Host header case manipulation. | A case-sensitivity flaw in Tinyauth’s forward-auth middleware (CVE-2026-77560) lets authenticated users bypass app-level access controls. For DPI and enterprise identity gateways, this highlights the critical need to normalize headers and enforce defense-in-depth beyond single auth proxies. |
| 4 | 2 | CVE-2026-85751 | Authentication bypass in internet-facing mail servers impacts foundational communications infrastructure across Government, Finance, Healthcare, and Digital Identity sectors. | Unauthenticated header spoofing in Mailu (CVE-2026-85751) bypasses webmail authentication, posing a direct risk to email infrastructure underpinning government, healthcare, and financial services. Patch or enforce REAL_IP_HEADER immediately. |
| 3 | 2 | CVE-2026-73547 | Foundational cloud-native edge proxy and service mesh component underpinning regulated and public digital service architectures, though exploitation requires non-default configurations. | Envoy proxy DoS (CVE-2026-73547) highlights a configuration-specific risk in cloud-native DPI architectures. While requiring non-default ext_authz setups, it underscores the need for strict hardening in public-facing edge proxies and service meshes. |
| 3 | 2 | CVE-2026-94412 | Finance sector relevance due to ERP system handling SME financial operations and procurement data. | Internal ERP flaws can turn a single compromised token into full administrative control over financial records. Enforce MFA and strict endpoint monitoring to protect business-critical data. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-15801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46649.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53940.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55074.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61674.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62182.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65654.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71543.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73546.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77523.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84990.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86473.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88406.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88407.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89139.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94129.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94368.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94381.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94401.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94495.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94496.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94497.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94501.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94532.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94624.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94627.md` — heuristic TIER 3/4
