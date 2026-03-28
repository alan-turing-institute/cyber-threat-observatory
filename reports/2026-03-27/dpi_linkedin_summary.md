# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-03-28 07:28:20Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-03-27`
- **Included count:** 3

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-33875 | Affects Digital Identity within Germany's healthcare infrastructure by enabling impersonation of medical professionals through malicious deep links in the Gematik Authenticator app. | A critical vulnerability in Germany's digital health identity system allows attackers to hijack authentications and impersonate doctors. This TIER 2 flaw impacts the Telematics Infrastructure used by healthcare workers, highlighting risks in internal mobile authentication flows. |
| 4 | 2 | CVE-2026-33758 | Affects OpenBao's OIDC/JWT authentication, a digital identity secrets management system used in enterprise environments. | OpenBao's OIDC/JWT XSS vulnerability (CVE-2026-33758) could allow attackers to steal tokens in authenticated sessions. This impacts Digital Identity infrastructure where secure token handling is critical. |
| 3 | 2 | CVE-2026-33992 | Affects Digital Identity and Government sectors due to authentication-based SSRF in pyLoad that can expose cloud metadata and credentials. | A TIER 2 SSRF vulnerability in pyLoad allows authenticated attackers to access internal services or cloud metadata, posing risks to Digital Identity and Government deployments. This highlights the importance of securing web interfaces even in self-hosted tools. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2019-25651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33757.md` — heuristic TIER 3/4
