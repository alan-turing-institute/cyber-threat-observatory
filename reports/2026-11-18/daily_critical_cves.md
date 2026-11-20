# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-20 13:07:05Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-18`
- **Included count:** 34

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 1 | CVE-2021-48023 | Unauthenticated RCE in widely deployed government and finance OA platform, confirmed exploited in the wild with no effective mitigations. | Critical unauthenticated RCE in Weaver E-cology OA systems is being actively exploited in the wild. Government and financial institutions relying on this platform for workflow management must patch immediately, as default configurations leave thousands of instances exposed. |
| 5 | 1 | CVE-2022-51034 | Unauthenticated SQLi in a government-deployed reservoir safety supervision platform, actively exploited in the wild with zero authentication barriers. | Critical infrastructure at risk: An unauthenticated SQL injection in a widely deployed government reservoir safety platform is being actively exploited in the wild. With no default authentication and public PoCs available, public-sector monitoring systems face immediate data breach and lateral movement threats. |
| 5 | 2 | CVE-2026-120285 | Foundational edge load balancer/WAF explicitly underpinning Finance, Government, Healthcare, and Digital Identity services with critical unauthenticated RCE/DoS risk. | F5 BIG-IP edge infrastructure faces a critical unauthenticated RCE vulnerability that could disrupt public-facing finance, government, and healthcare portals. While requiring a specific iRule configuration, the widespread deployment of BIG-IP at the network edge makes prompt hotfix application essential for DPI resilience. |
| 5 | 2 | CVE-2026-120292 | Foundational edge infrastructure (F5 BIG-IP) securing load balancing, WAF, and identity endpoints across Government, Finance, Healthcare, and Digital Identity sectors. | F5 BIG-IP’s critical stack-based buffer overflow (CVE-2026-120292) threatens the edge infrastructure underpinning government, finance, and healthcare services. While exploitation requires a specific iRule configuration, the unauthenticated RCE/DoS risk demands immediate patching for any regulated environment relying on BIG-IP for secure public-facing access. |
| 5 | 2 | CVE-2026-121812 | F5 BIG-IP APM is a core IdAM/SSO gateway for regulated sectors; a DoS here directly disrupts authentication and secure access for government, finance, and healthcare services. | F5 BIG-IP APM DoS (CVE-2026-121812) underscores the fragility of edge identity gateways. Though it requires a non-default debug key, the potential to knock out public-facing SSO and MFA services makes it a critical watch for DPI operators. |
| 5 | 2 | CVE-2026-123637 | Critical RCE/DoS in F5 BIG-IP APM, a core IdAM gateway fronting public-facing SSO and national digital identity infrastructure. | F5 BIG-IP APM deployments face a critical, unauthenticated RCE risk that could disrupt national digital identity and SSO gateways. While requiring a specific policy configuration, the public-facing data plane exposure makes immediate hotfixing essential for regulated identity providers. |
| 5 | 2 | CVE-2026-125272 | Unauthenticated DoS in F5 BIG-IP APM disrupts public-facing identity gateways and authentication flows, directly impacting Digital Identity infrastructure. | F5 BIG-IP APM faces a critical unauthenticated DoS risk that can crash identity gateways and block user access. Organizations relying on APM for public authentication must apply hotfixes immediately to protect digital identity services. |
| 5 | 2 | CVE-2026-126336 | Directly impacts SAML Service Provider and encrypted assertion processing in F5 BIG-IP APM, a foundational Digital Identity gateway extensively deployed across Government, Finance, and Healthcare sectors. | A TIER 2 DoS in F5 BIG-IP APM’s SAML processing could disrupt federated identity gateways for public and regulated services. Verify encrypted assertion configurations and ensure HA failover is active to maintain resilient citizen and enterprise access. |
| 5 | 2 | CVE-2026-126822 | Unauthenticated DoS in F5 BIG-IP APM SAML SP processing disrupts public-facing identity federation and SSO gateways critical to government, finance, and healthcare digital services. | A TIER 2 DoS in F5 BIG-IP APM’s SAML processing can crash public-facing SSO gateways, highlighting the fragility of identity federation layers in digital public infrastructure. Ensure your SAML SP configurations are patched or restricted to maintain citizen and enterprise access continuity. |
| 5 | 1 | CVE-2026-132224 | TIER 1 supply-chain flaw in a public SaaS/CDN platform actively exploited to inject payment skimmers into major Finance and public-facing web services. | A critical, actively exploited supply-chain vulnerability in a widely used web experimentation platform just compromised hundreds of major sites, including major banks and media outlets. For DPI and regulated sectors, this underscores the urgent need for strict CSP/SRI enforcement and continuous monitoring of third-party SaaS dependencies. |
| 5 | 2 | CVE-2026-75522 | Directly compromises Digital Identity and Government sectors by enabling unauthenticated forgery of eIDAS/EUDI verifiable credentials in national ID infrastructure. | A ready-to-use PoC now exists for a critical flaw in the openid4vp library, allowing attackers to forge trusted digital identity credentials by bypassing cryptographic validation. This directly threatens eIDAS/EUDI compliance and citizen-facing verification services, making immediate patching to v0.8.1 essential for all relying parties. |
| 4 | 1 | CVE-2012-20007 | Critical unauthenticated RCE in ThinkPHP framework, widely deployed in public-facing enterprise and government web services with confirmed in-wild exploitation. | ThinkPHP's critical RCE (CVE-2012-20007) remains actively exploited in the wild, posing severe risks to public-facing enterprise and government web services built on this foundational PHP framework. |
| 4 | 2 | CVE-2012-20008 | Authenticated LFI/RCE in openSIS, a widely deployed public education platform impacting government/civic data and school service continuity. | Public school districts using openSIS are facing active exploitation of an authenticated LFI flaw that can lead to RCE and student PII exposure. Upgrading to v9.0+ and enforcing MFA are essential to secure civic education infrastructure. |
| 4 | 2 | CVE-2021-48022 | Self-hosted enterprise messaging platform widely deployed in government, finance, and healthcare sectors; unauthenticated message dump threatens secure internal communications and compliance data. | Confirmed in-wild exploitation of Rocket.Chat’s unauthenticated message dump vulnerability highlights the risks of self-hosted collaboration tools in regulated sectors. Agencies and financial institutions relying on internal comms platforms should verify patching and disable unused LiveChat features immediately. |
| 4 | 2 | CVE-2026-107950 | Unauthenticated XXE in public-facing HCL Commerce storefront APIs directly threatens enterprise e-commerce and payment processing infrastructure (Finance sector). | Enterprise e-commerce platforms face a critical unauthenticated XXE flaw in their public storefront APIs, risking credential theft and service disruption. Finance and retail operators should prioritize patching HCL Commerce and hardening XML parsers to protect consumer financial data flows. |
| 4 | 2 | CVE-2026-120722 | Core edge load-balancing infrastructure (F5 BIG-IP) widely deployed in government and enterprise networks, with unauthenticated RCE/DoS risk impacting public-facing digital services. | F5 BIG-IP edge devices face a critical unauthenticated RCE/DoS risk (CVE-2026-120722) tied to custom iRule configurations. Government and enterprise operators should audit DNS::scrape usage and patch immediately to protect public-facing digital services. |
| 4 | 2 | CVE-2026-121805 | Critical unauthenticated RCE/DoS in F5 BIG-IP edge load balancers, foundational infrastructure explicitly tied to Finance, Government, and Healthcare deployments. | Internet-facing F5 BIG-IP load balancers face a critical buffer overflow risk that could enable remote code execution or service disruption. Regulated sectors relying on F5 for edge protection should prioritize hotfix deployment, even though exploitation requires a specific fraud-protection configuration. |
| 4 | 2 | CVE-2026-123007 | Foundational reverse proxy/load balancer underpinning digital identity, finance, healthcare, and government services; critical unauthenticated RCE in internet-exposed infrastructure. | Critical HTTP/2 RCE in NGINX threatens the foundational routing layer for public services across finance, healthcare, and government. While exploitation requires high bandwidth and ASLR bypass, patching or disabling HTTP/2 remains urgent for internet-exposed DPI deployments. |
| 4 | 2 | CVE-2026-123633 | Foundational edge proxy/load balancer vulnerability underpinning public-facing digital services across government, finance, healthcare, and identity sectors. | NGINX remains the backbone of public-facing digital infrastructure, making this TIER 2 RCE/DoS flaw a priority for any organization running citizen-facing or regulated web services. Patch or disable HTTP/2 immediately to protect your edge layer. |
| 4 | 2 | CVE-2026-130754 | Critical OAuth/OIDC authentication bypass in a Laravel admin panel, directly impacting Digital Identity verification and session management. | A critical TIER 2 flaw in LaraDashboard's social login flow allows attackers to hijack admin accounts via unverified OAuth emails. Organizations relying on social auth for digital identity must patch or disable the feature immediately. |
| 4 | 2 | CVE-2026-130787 | Tier 2 missing authorization in Frappe ERPNext exposes regulated financial, tax, and payment data across tenant boundaries, directly impacting Finance and Government digital infrastructure. | ERP systems handling public or corporate finances face a silent data leak risk: CVE-2026-130787 lets authenticated low-privilege users bypass authorization to extract sensitive tax and payment records. Patch to 16.35.0+ and harden RBAC to protect regulated financial data. |
| 4 | 2 | CVE-2026-55171 | Critical authentication bypass in Open OnDemand HPC portals, directly impacting government-funded research centers and national labs that rely on it as a public-facing access gateway. | National labs and public research institutions should patch Open OnDemand immediately: a default OIDC passphrase fallback allows attackers to forge session cookies and bypass authentication on public-facing HPC portals. #CyberSecurity #DPI #GovTech |
| 4 | 2 | CVE-2026-76100 | Finance sector: unauthenticated payment verification bypass in a self-hosted payment gateway enables direct ledger corruption and financial fraud. | Payment gateways handling public transactions must enforce strict cryptographic verification. This TIER 2 flaw in OwnPay allows attackers to forge webhooks and bypass payment checks, highlighting the critical need for hardened financial infrastructure. |
| 3 | 2 | CVE-2026-116953 | Tier 2 remote buffer overflow in F5 BIG-IP edge load balancers, classified as general infrastructure but foundational for securing public-facing government, finance, and healthcare services. | F5 BIG-IP administrators should prioritize patching CVE-2026-116953, a Tier 2 stack overflow that can crash edge traffic management or enable RCE. Audit and remove GENERICMESSAGE::route iRules on internet-facing virtual servers to protect critical public infrastructure. |
| 3 | 2 | CVE-2026-118899 | Tier 2 unauthenticated DoS in NGINX reverse proxies threatens availability of public-facing web infrastructure underpinning DPI services. | A new Tier 2 vulnerability in NGINX allows attackers to crash public-facing web servers via default TLSv1.3 configurations. DPI operators should prioritize patching or temporarily restrict TLS versions to safeguard service availability. |
| 3 | 2 | CVE-2026-129961 | Unauthenticated RCE in widely deployed ISP/telecom management platforms risks critical connectivity infrastructure and public digital service availability. | TIER 2 alert: A trivial, unauthenticated RCE in LMS helpdesk systems could let attackers pivot into ISP management networks. Patching email intake filters is critical for telecom operators protecting public connectivity. |
| 3 | 2 | CVE-2026-130727 | Tier 2 authorization bypass in NocoDB's public shared views risks uncontrolled data exposure for organizations deploying the platform for citizen-facing or regulated data sharing. | Public data portals built on NocoDB face a critical row-level filter bypass, allowing attackers to enumerate and extract hidden records via shared links. Patching is essential for any organization exposing databases to the public. |
| 3 | 2 | CVE-2026-130760 | Tier 2 unauthenticated DoS in Fleet MDM endpoints, critical for public sector and enterprise device management infrastructure. | Unauthenticated DoS in Fleet MDM could cripple public sector device management. Patch to 4.86.2 or restrict internet exposure to maintain operational continuity. |
| 3 | 2 | CVE-2026-132140 | Unauthenticated remote DoS on widely deployed enterprise edge routers explicitly noted as foundational infrastructure across government, finance, and healthcare networks. | Enterprise perimeter routers like the DrayTek Vigor2960 are critical to public and regulated sector networks. This unauthenticated DoS vulnerability highlights the need to harden internet-facing management interfaces and enforce strict access controls across government and financial infrastructure. |
| 3 | 2 | CVE-2026-132208 | Finance sector relevance due to trivial extraction of hardcoded credentials exposing SME invoicing, tax compliance, and billing databases. | Hardcoded credentials in a popular SME accounting app (winCRM) expose backend databases and email servers with zero effort. A stark reminder for finance and compliance teams to audit third-party binaries and enforce backend credential rotation. |
| 2 | 2 | CVE-2026-123634 | Foundational web infrastructure (NGINX) underpins public-facing government, finance, and healthcare portals; DoS/RCE risk affects regulated service availability. | NGINX use-after-free flaw (CVE-2026-123634) poses a Tier 2 risk to public-facing digital services. While exploitation requires niche proxy/SSI configurations, organizations running citizen or banking portals should audit reverse proxy setups and patch to 1.30.7/1.31.9. |
| 2 | 2 | CVE-2026-130675 | General infrastructure RCE in a commercial CMS explicitly noted for potential government and regulated e-commerce deployments, requiring urgent patching to prevent unauthenticated server compromise. | Unauthenticated RCE in Craft CMS (CVE-2026-130675) threatens public-facing digital services. Though sector-agnostic, its use in government and regulated e-commerce makes patching to v5.11.4 a priority for DPI resilience. |
| 2 | 2 | CVE-2026-19707 | Tier 2 RCE/DoS in an enterprise API gateway/WAF that serves as critical edge infrastructure for regulated and public-facing digital services. | A Tier 2 heap overflow in Airlock Gateway’s Smart Form Protection could allow RCE or DoS on perimeter security appliances. While configuration-dependent, this underscores the need to audit optional WAF features and patch edge gateways protecting citizen and enterprise APIs. |
| 2 | 2 | CVE-2026-95787 | Critical unauthenticated admin bypass in enterprise networking (HPE ArubaOS) widely deployed as foundational infrastructure in government, finance, and healthcare sectors. | Enterprise networks form the backbone of digital public services. This critical auth bypass in HPE ArubaOS highlights the need for strict management-plane segmentation and patching in regulated environments. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-64441.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107515.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107516.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107518.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107519.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109857.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111507.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113497.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116446.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116449.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127143.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130644.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130677.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130726.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130769.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130784.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131820.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132144.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132212.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132229.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132231.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132232.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132233.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132240.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132241.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15263.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-30502.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63415.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73968.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76414.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76415.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76416.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76421.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76515.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76516.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82171.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95789.md` — heuristic TIER 3/4
