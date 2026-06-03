# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-06-03 07:21:50Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-02`
- **Included count:** 4

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-49448 | Affects Digital Identity systems as authentik is an identity provider used for authentication and authorization, involving core identity management functions including user sessions, access control, and credential handling mechanisms. | A critical authentication bypass vulnerability in authentik allows attackers to skip authentication stages under specific conditions. This impacts digital identity infrastructure where proper access controls are essential. |
| 4 | 2 | CVE-2026-0611 | Healthcare - affects Spacelabs Healthcare Sentinel systems used for cardiology information management and patient data processing in clinical environments. | A TIER 2 vulnerability in Spacelabs Healthcare Sentinel systems could allow unauthenticated RCE via an exposed .NET Remoting channel, impacting healthcare digital infrastructure. While requiring explicit configuration changes, it highlights risks in medical device management and patient data security. |
| 4 | 2 | CVE-2026-34906 | Affects Digital Identity in educational ERP systems managing student and faculty access control. | A critical SSTI vulnerability in Wirtualna Uczelnia, an educational ERP platform, allows unauthenticated RCE. This impacts digital identity systems used by universities for managing student and staff accounts. |
| 3 | 2 | CVE-2026-32625 | Relevant to Government infrastructure as an AI chat platform that may process sensitive data in public sector deployments, exposing cryptographic secrets and database credentials. | A critical info disclosure flaw in LibreChat allows authenticated users to leak sensitive environment variables like JWT_SECRET and MONGO_URI. While not directly a Digital Identity issue, it could impact government systems using AI platforms for handling sensitive data. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-10629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7312.md` — heuristic TIER 3/4
