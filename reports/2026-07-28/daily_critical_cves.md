# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-30 04:36:30Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-28`
- **Included count:** 11

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-54603 | Directly compromises OAuth 2.0/OIDC bearer tokens in the widely used Ruby oauth2 gem, impacting Digital Identity infrastructure and SSO deployments. | A TIER 2 flaw in the Ruby oauth2 gem leaks bearer tokens via protocol-relative redirects, threatening OAuth/OIDC-based SSO and digital identity systems. Patch to v2.0.22+ to protect federated authentication flows. |
| 4 | 2 | CVE-2026-13161 | Healthcare sector: unauthenticated SQLi in a clinical appointment plugin risks patient data privacy and service disruption. | Healthcare providers using public-facing booking plugins must patch immediately to prevent unauthenticated database access and patient data exposure. This TIER 2 flaw highlights the need for strict input validation in clinical scheduling tools. |
| 4 | 2 | CVE-2026-16184 | TIER 2 authentication bypass in IBM WebSphere, a foundational middleware explicitly deployed across finance, healthcare, and government sectors to host critical public-facing services. | IBM WebSphere’s authentication bypass (CVE-2026-16184) highlights a critical patching window for enterprises hosting regulated public services. While exploitation requires high complexity, the lack of workarounds means finance, healthcare, and government deployments must prioritize immediate updates to protect citizen-facing applications. |
| 4 | 2 | CVE-2026-54605 | Digital Identity sector: core OAuth authentication library vulnerable to SSRF and credential disclosure, impacting identity management in regulated web applications. | A TIER 2 flaw in a widely used Ruby OAuth gem exposes authentication flows to SSRF and credential leakage. While standard deployments with fixed providers remain safe, multi-tenant and custom-integration environments should patch immediately to protect identity infrastructure. |
| 4 | 2 | CVE-2026-54635 | Finance sector: Enables unauthenticated injection of forged blockchain transaction events into payment and account-state handlers, risking financial loss and ledger corruption. | A TIER 2 authentication bypass in a TON blockchain SDK allows attackers to forge transaction webhooks, directly threatening financial integrity in crypto-asset platforms. Developers should patch to v2.2.1 and enforce external event validation to protect payment pipelines. |
| 3 | 2 | CVE-2026-14446 | Critical unauthenticated privilege escalation in IBM WebSphere, a foundational enterprise middleware platform widely deployed in regulated finance, government, and healthcare backends. | A CVSS 9.8 flaw in IBM WebSphere’s admin console allows unauthenticated privilege escalation and potential RCE. While typically internal-facing, this underscores the critical need for strict network segmentation and patching in regulated enterprise environments hosting public digital services. |
| 3 | 2 | CVE-2026-14512 | Critical pre-auth RCE in foundational enterprise middleware that underpins regulated sector applications and DPI services. | Pre-authentication RCE in IBM WebSphere (CVE-2026-14512) demands immediate patching for enterprises hosting critical applications. With no workarounds available, network segmentation and WAF rules are essential while deploying fixes across regulated environments. |
| 3 | 2 | CVE-2026-14959 | Tier 2 authenticated RCE in IBM Aspera Faspex, a public-facing secure file transfer portal explicitly noted for widespread deployment in healthcare, finance, and government environments. | Internet-exposed file transfer portals are critical infrastructure for regulated sectors. This Tier 2 RCE in IBM Aspera Faspex underscores the need for rapid patching and strict access controls to protect sensitive cross-organizational data flows. |
| 3 | 2 | CVE-2026-54655 | CI/CD and developer tooling vulnerability that poses a software supply-chain risk to Government and Finance pipelines building regulated DPI systems. | A TIER 2 code injection flaw in a widely used Python schema generator could silently compromise CI/CD pipelines. DPI teams should audit developer tooling and enforce strict schema validation to protect regulated software supply chains. |
| 3 | 2 | CVE-2026-59248 | Foundational HTTP/2/3 parsing library for public-facing APIs and microservices, posing a high-severity unauthenticated DoS risk to internet-exposed digital services. | A single crafted HTTP/2 header can crash Erlang/Elixir web servers via memory exhaustion. Tier 2 alert for teams running Phoenix, Cowboy, or RabbitMQ management interfaces—patch cowlib to 2.19.0+ and enforce header limits. |
| 2 | 2 | CVE-2026-14974 | TIER 2 RCE in IBM WebSphere, a foundational enterprise middleware widely underpinning regulated finance, government, and healthcare application stacks. | Enterprise middleware remains a critical attack surface for regulated sectors. This TIER 2 deserialization flaw in IBM WebSphere highlights the need for strict network segmentation and patching in mission-critical application tiers. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2024-14041.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14528.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14973.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14981.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15025.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16496.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43910.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47427.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47483.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47726.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48060.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48390.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48391.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48393.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48395.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48396.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49258.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50736.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-51252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-51254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-51259.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-51271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-51273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-51274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54545.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54609.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54638.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54654.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54656.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54690.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55389.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55390.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55391.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57510.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59878.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62426.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62427.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66745.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7769.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8164.md` — heuristic TIER 3/4
