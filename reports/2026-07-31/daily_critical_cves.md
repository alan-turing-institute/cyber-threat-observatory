# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-01 17:46:02Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-31`
- **Included count:** 3

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-11770 | Core LDAP directory service vulnerability exposing authentication metadata and password storage schemes, directly impacting centralized Digital Identity infrastructure. | Unauthenticated LDAP injection in 389 Directory Server exposes critical identity metadata, highlighting the need to harden internal IdAM deployments and disable anonymous binds in national digital infrastructure. |
| 4 | 2 | CVE-2026-15722 | Digital Identity sector: Core LDAP/IdAM directory server flaw enables unauthenticated DoS, disrupting authentication and identity management for enterprise and public-sector systems. | A remote, unauthenticated DoS in 389 Directory Server highlights the critical need to harden internal identity infrastructure. Even behind firewalls, default anonymous access can cripple enterprise authentication—patch and restrict LDAP replication ports now. |
| 3 | 2 | CVE-2026-17566 | Critical RCE in pgAdmin 4, a widely deployed database administration console that underpins backend systems for regulated sectors including finance, healthcare, and government. | Database administration tools are the silent backbone of regulated digital services. This Tier 2 RCE in pgAdmin 4 highlights why internal-facing infrastructure still demands strict patching and network segmentation to protect critical data pipelines. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-67650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10079.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14537.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14538.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14830.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17347.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17561.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18358.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18481.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-34641.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43830.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43831.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46593.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55100.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56670.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62391.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67607.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9044.md` — heuristic TIER 3/4
