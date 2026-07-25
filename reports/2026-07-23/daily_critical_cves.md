# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-25 12:25:19Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-23`
- **Included count:** 11

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-10697 | Authentication bypass in Progress MOVEit Transfer threatens secure file exchanges across Finance, Healthcare, and Government sectors, risking exfiltration of regulated PII, PHI, and citizen data. | A new TIER 2 authentication bypass in Progress MOVEit Transfer (CVE-2026-10697) exposes a legacy endpoint widely used by banks, hospitals, and government agencies. With no public exploit yet, now is the time to patch or disable legacy API paths before threat actors weaponize this critical file transfer gateway. |
| 5 | 2 | CVE-2026-56165 | Critical unauthenticated RCE in Microsoft Account, a foundational Digital Identity/IdAM platform handling authentication and token issuance for enterprise and public services. | A critical, unauthenticated RCE in Microsoft Account (CVE-2026-56165) underscores the systemic risk to foundational Digital Identity infrastructure. Organizations relying on Microsoft's IdAM stack for enterprise or citizen-facing services should prioritize patching and reinforce identity hygiene ahead of vendor updates. |
| 5 | 2 | CVE-2026-63359 | Critical unauthenticated authentication bypass and SQL injection in VINE, a public-facing victim notification platform deployed by state and local governments, directly impacting the Government sector. | A critical, unauthenticated flaw in the VINE victim notification platform exposes sensitive PII and credentials across state and local government deployments. With zero exploitation barriers, justice and public safety agencies must prioritize immediate patching and WAF hardening to protect citizen-facing services. |
| 4 | 2 | CVE-2026-59547 | Unauthenticated broken access control in a widely deployed WooCommerce PayPal payment gateway exposes financial transaction data and payment routing, directly impacting the Finance sector of digital public infrastructure. | Public-facing e-commerce platforms handling real money are prime targets for unauthenticated access flaws. This TIER 2 vulnerability in a popular PayPal gateway plugin underscores the need for strict authorization checks and rapid patching in any digital service processing financial transactions. |
| 4 | 2 | CVE-2026-59554 | Finance sector: Unauthenticated broken authentication in a WooCommerce payment gateway plugin directly threatens financial transaction integrity and e-commerce payment flows. | A TIER 2 broken authentication flaw in the Ziina WooCommerce payment plugin could let attackers bypass checkout controls and manipulate transactions. For finance and e-commerce teams, this underscores the critical need to patch payment gateways and enforce strict endpoint access controls. |
| 4 | 2 | CVE-2026-61954 | Finance sector: unauthenticated broken access control in a payment gateway plugin threatens transaction integrity and PCI-DSS compliance. | Payment gateways are critical financial infrastructure. This unauthenticated flaw in the PayU India WordPress plugin could allow attackers to manipulate transactions or steal payment data without credentials, so patch immediately to protect revenue and compliance. |
| 4 | 2 | CVE-2026-65761 | Unauthenticated SQLi in a public-facing eCommerce extension exposes customer PII and payment data, directly impacting Finance-sector digital storefronts and regulated transaction environments. | A ready-to-use exploit for a critical SQL injection in a popular eCommerce extension is now public, putting online storefronts and customer financial data at immediate risk. Organizations running vulnerable versions must patch urgently to prevent unauthenticated database extraction and potential regulatory breaches. |
| 3 | 2 | CVE-2026-21655 | Unauthenticated RCE in physical security/access control platforms risks lateral movement and operational disruption across critical infrastructure and government facilities. | Physical security systems are increasingly targeted as pivot points into critical infrastructure. This TIER 2 deserialization flaw in Johnson Controls access control platforms enables unauthenticated RCE on internal OT networks, underscoring the urgency of network segmentation and timely patching for regulated environments. |
| 3 | 2 | CVE-2026-56167 | Foundational cloud search/AI infrastructure explicitly tied to powering workflows across Healthcare, Finance, Government, and Digital Identity sectors. | CVE-2026-56167 exposes an SSRF privilege escalation risk in Microsoft Azure AI Search, a backend service widely adopted across regulated sectors. While exploitation requires valid credentials, its default public reachability and strategic role in enterprise AI pipelines warrant immediate access reviews and private endpoint enforcement for DPI deployments. |
| 3 | 2 | CVE-2026-65760 | Finance sector relevance due to exposure of transaction histories, billing data, and payment-related invoices in public-facing e-commerce platforms. | A critical IDOR flaw in a popular Joomla e-commerce extension allows authenticated users to scrape order histories, billing addresses, and invoices for any customer. For DPI and regulated finance environments, this underscores the non-negotiable need for strict ownership verification on all transaction endpoints. |
| 2 | 2 | CVE-2026-14282 | Unauthenticated RCE in a widely deployed WordPress plugin impacts public-facing government, healthcare, and finance web portals relying on general web infrastructure. | Critical unauthenticated RCE in the GoDAM WordPress plugin (CVE-2026-14282) poses a direct risk to public-facing digital services. Agencies and regulated sectors should audit WordPress deployments and enforce strict upload directory controls immediately. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2024-58330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12421.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15212.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15966.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15968.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16796.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24552.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28698.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-34496.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43823.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47670.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47743.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50032.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50039.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50103.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57397.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57699.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57735.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57769.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57784.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57809.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59512.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59517.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64809.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64812.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64813.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64815.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6516.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65461.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65477.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65481.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65488.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65497.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65510.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65511.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65532.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65605.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65606.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65607.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65690.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65703.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7232.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7534.md` — heuristic TIER 3/4
- `TIER_4_CVE-2024-58023.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-64611.md` — heuristic TIER 3/4
