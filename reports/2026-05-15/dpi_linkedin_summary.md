# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-05-16 07:23:17Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-05-15`
- **Included count:** 2

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-41258 | High-impact RCE vulnerability in OpenMRS healthcare systems affects patient data management and could lead to PHI exposure. | A critical SSTI flaw in OpenMRS allows remote code execution and PHI exfiltration, making it a top concern for healthcare DPI. Organizations using EMR systems must act fast to patch this vulnerability. |
| 4 | 2 | CVE-2026-44551 | Affects LDAP-based authentication in Open WebUI, impacting Digital Identity by enabling account takeover through empty password bypass. | A critical auth bypass in Open WebUI allows full account takeovers via LDAP when empty passwords are accepted. This highlights the importance of securing identity access mechanisms in internal AI platforms. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2021-47965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7373.md` — heuristic TIER 3/4
