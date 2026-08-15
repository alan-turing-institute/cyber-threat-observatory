# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-15 03:22:58Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-14`
- **Included count:** 2

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-19764 | Unauthenticated SQLi in a government/public safety dispatch platform enables credential theft and lateral movement within critical state telecom infrastructure. | Even internal-only management consoles are high-value targets: an unauthenticated SQLi in a government dispatch platform shows how easily attackers can harvest credentials and pivot within critical state telecom networks. For DPI operators, this underscores the need for strict network segmentation and WAF rules on internal-facing admin interfaces. |
| 4 | 2 | CVE-2026-19870 | Finance sector relevance: cross-tenant authorization bypass in a CRM payroll module exposes sensitive salary and banking (IBAN) data, threatening financial integrity and regulatory compliance. | A TIER 2 flaw in a CRM payroll module allows authenticated users to bypass tenant boundaries and access or manipulate salary and banking data. For finance and HR tech leaders, this highlights the critical need for strict RBAC and query scoping in multi-tenant financial workflows. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-19762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72835.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72836.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72859.md` — heuristic TIER 3/4
