# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-28 09:23:49Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-27`
- **Included count:** 13

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-101042 | Digital Identity: Improper authentication in Parse Server OAuth adapters enables identity spoofing and account pre-hijacking, directly impacting IdAM and session verification flows. | CVE-2026-101042 exposes a critical flaw in Parse Server's OAuth handling, allowing attackers to spoof external provider identities and hijack accounts. Organizations relying on code-based auth adapters must patch immediately to protect their digital identity infrastructure. |
| 5 | 1 | CVE-2026-88771 | Critical unauthenticated RCE in Citrix NetScaler ADC/Gateway, a core Digital Identity and remote access proxy actively exploited in the wild and listed on CISA KEV. | Active zero-day exploitation of Citrix NetScaler gateways poses an immediate threat to digital public infrastructure. As a critical IdAM and remote access proxy, unpatched appliances face unauthenticated RCE, demanding urgent patching to protect citizen and enterprise access layers. |
| 5 | 1 | CVE-2026-88772 | Foundational edge infrastructure for government, healthcare, finance, and digital identity services; unauthenticated RCE on default-configured NetScaler gateways directly threatens citizen data and critical public access. | Citrix NetScaler ADC/Gateway faces active exploitation via a critical DTLS overflow (CVE-2026-88772), now on CISA’s KEV catalog. With no workarounds and default configurations vulnerable, government, healthcare, and financial edge deployments must patch immediately to protect citizen access and identity services. |
| 4 | 2 | CVE-2026-100869 | Finance sector relevance due to direct impact on payment integrity and merchant revenue in public-facing e-commerce deployments. | E-commerce platforms handling public payments face direct financial risk from authorization flaws. CVE-2026-100869 in Sylius allows customers to trigger unauthorized refunds, highlighting the need for strict API controls in regulated transaction environments. |
| 4 | 2 | CVE-2026-100870 | TIER 2 Host header injection in Sylius e-commerce enables unauthenticated admin takeover, directly impacting Finance sector payment processing and customer account security. | E-commerce platforms handling payments and customer data are prime targets. CVE-2026-100870 shows how a simple Host header injection can bypass Sylius admin password resets, risking full store compromise and payment data exposure. Patch or pin trusted hosts immediately. |
| 4 | 2 | CVE-2026-100872 | Finance sector: Unauthenticated payment amount manipulation in Sylius e-commerce framework directly impacts transaction integrity and financial operations. | E-commerce platforms handling public transactions face direct financial risk from unauthenticated checkout logic flaws. CVE-2026-100872 in Sylius allows attackers to inflate order values post-payment capture, highlighting the need for strict transaction reconciliation in digital commerce infrastructure. |
| 4 | 2 | CVE-2026-100888 | Foundational DKIM email authentication infrastructure underpinning secure communications and trust for government, finance, and healthcare sectors. | A public-facing, unauthenticated DoS in OpenDKIM threatens inbound email trust for regulated sectors. With no official vendor patch, MTA-level header filtering is critical to keep government and enterprise mail flows resilient. |
| 4 | 2 | CVE-2026-88773 | Critical HTTP request smuggling in Citrix NetScaler ADC/Gateway, a foundational edge proxy explicitly tied to Government, Finance, and Healthcare remote access deployments. | Unauthenticated HTTP request smuggling in Citrix NetScaler could bypass perimeter controls and hijack sessions across government, finance, and healthcare deployments. Patch immediately to protect critical edge infrastructure. |
| 4 | 2 | CVE-2026-88774 | TIER 2 policy bypass in Citrix NetScaler ADC/Gateway, foundational edge infrastructure for government and regulated sector remote access and application delivery. | Citrix NetScaler ADC/Gateway deployments face a TIER 2 policy bypass risk that could undermine perimeter security for government and enterprise remote access. While requiring specific URL-based policy configurations, the flaw highlights the need to audit edge appliance rules and apply patches promptly to protect citizen and employee access channels. |
| 4 | 2 | CVE-2026-88775 | Impacts Digital Identity, Government, and Finance sectors by threatening the availability of foundational SSO, VPN, and remote access gateways used for public and enterprise identity infrastructure. | Unauthenticated DoS in Citrix NetScaler ADC/Gateway threatens the availability of critical remote access and SSO gateways. A vital patch for Digital Identity, Government, and Finance infrastructure relying on these public-facing entry points. |
| 4 | 2 | CVE-2026-88778 | Digital Identity sector: TIER 2 TCP ISN prediction flaw in Citrix NetScaler ADC/Gateway, a default-vulnerable edge gateway critical for enterprise remote access and zero-trust session management. | Citrix NetScaler ADC/Gateway deployments face a default-vulnerable TCP ISN prediction flaw (CVE-2026-88778) that enables session hijacking on public-facing edge gateways. With immediate CLI mitigation available, DPI operators managing remote access and zero-trust identity proxies should verify Enhanced ISN Generation is enabled today. |
| 3 | 2 | CVE-2026-100889 | General infrastructure: OpenDKIM underpins enterprise and public-sector email authentication; remote DoS disrupts critical inbound communication pipelines. | Unauthenticated remote DoS in OpenDKIM (CVE-2026-100889) threatens enterprise and public-sector email gateways. A single crafted email can crash DKIM verification, disrupting inbound mail pipelines until patched. |
| 2 | 2 | CVE-2026-100886 | General infrastructure risk: unauthenticated root RCE in widely deployed enterprise/public sector NVRs enables lateral movement and surveillance data breach. | CVE-2026-100886 exposes a critical unauthenticated RCE in Seetong NVRs, reminding enterprises that internal debug ports can become lateral movement gateways. Strict network segmentation and firewall rules are essential to protect surveillance infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-71423.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-71425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-71426.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100834.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100835.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100838.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100841.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100859.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101060.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101062.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101086.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89102.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96280.md` — heuristic TIER 3/4
