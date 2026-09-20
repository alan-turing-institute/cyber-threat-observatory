# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-20 09:35:25Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-16`
- **Included count:** 22

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-18212 | Digital Identity sector: unauthenticated DoS in Keycloak's SAML endpoint crashes public-facing IdP instances, disrupting enterprise and government SSO flows. | A TIER 2 DoS in Keycloak's SAML implementation can crash public-facing identity providers with zero authentication barriers. For DPI and regulated sectors relying on SSO, this highlights the critical need for rate-limiting and rapid patching of core IdAM gateways. |
| 5 | 2 | CVE-2026-20192 | Core IdAM platform (Cisco ISE) with actively exploited auth/authz bypasses, directly impacting digital identity and network access controls across government, healthcare, and finance. | Actively exploited CVSS 10.0 flaws in Cisco ISE expose a critical gap in enterprise digital identity infrastructure. Even behind firewalls, compromised network access control platforms can neutralize internal segmentation and credential management—urgent patching required for regulated sectors. |
| 5 | 2 | CVE-2026-20194 | Core enterprise IdAM platform (Cisco ISE) handling authentication, authorization, and credential management, with direct relevance to Digital Identity, Government, Healthcare, and Finance sectors. | Critical infrastructure relies on robust identity management, but a CVSS 9.1 flaw in Cisco ISE exposes sensitive credentials and enables unrestricted file uploads. Organizations in regulated sectors must prioritize patching to protect their digital identity foundations and maintain zero-trust network integrity. |
| 5 | 2 | CVE-2026-20237 | Core Digital Identity infrastructure (Cisco ISE) with unauthenticated RCE/path traversal flaws, directly impacting network access control and credential validation in government, healthcare, and finance. | Unauthenticated path traversal flaws in Cisco ISE (CVSS 9.9) threaten foundational network identity and access control. With no workarounds, regulated sectors must prioritize patching to prevent lateral movement and credential compromise. |
| 5 | 2 | CVE-2026-74909 | Authorization bypass in Keycloak policy enforcer impacts core Digital Identity infrastructure, allowing authenticated users to access restricted endpoints in public-facing IdP deployments. | Keycloak deployments face a high-severity authorization bypass (CVE-2026-74909) where malformed URI encoding lets authenticated users skirt policy enforcers. A critical patch for this TIER 2 flaw is essential for any organization relying on Keycloak for digital identity and access management. |
| 5 | 2 | CVE-2026-76423 | Critical unauthenticated admin bypass in Cisco ISE, a core Digital Identity and AAA platform managing enterprise authentication, authorization, and network access policies. | A TIER 2 critical flaw in Cisco ISE allows unauthenticated attackers to fully bypass authentication and seize administrative control of enterprise identity and network access policies. For DPI and regulated sectors relying on Zero Trust and AAA infrastructure, patching this internal gatekeeper is urgent to prevent lateral movement and credential harvesting. |
| 5 | 2 | CVE-2026-76460 | Critical authentication bypass in Cisco ISE, a core enterprise IdAM/AAA platform, enables unauthenticated root access and directly threatens digital identity infrastructure across government, healthcare, and finance sectors. | Actively exploited in the wild and on the CISA KEV catalog, this critical Cisco ISE flaw bypasses authentication to grant root access. For DPI operators, securing internal IdAM platforms is no longer optional—patch and segment immediately to protect your digital identity backbone. |
| 5 | 2 | CVE-2026-79651 | Directly impacts core Digital Identity infrastructure (Keycloak/SSO), causing unauthenticated DoS that blocks all authentication flows for government and enterprise portals. | A new TIER 2 vulnerability in Keycloak allows unauthenticated attackers to crash authentication services via simple HTTP requests, locking out users across government and enterprise SSO deployments. With no default mitigations, organizations relying on this core IdAM platform must prioritize patching to maintain digital identity availability. |
| 5 | 2 | CVE-2026-80274 | Foundational DNS infrastructure (BIND 9) DoS cascades across Digital Identity, Finance, Healthcare, and Government sectors. | DNS is the backbone of DPI. A trivial-to-trigger DoS in BIND 9 resolvers can cascade across government, finance, and healthcare networks, halting authentication and services. Patch immediately. |
| 5 | 2 | CVE-2026-81642 | Foundational DNS/DNSSEC infrastructure underpinning Government, Finance, and Healthcare digital services; RCE/DoS on resolvers disrupts all dependent public and regulated systems. | Critical RCE in Unbound DNSSEC validator (CVE-2026-81642) threatens foundational name resolution for government, finance, and healthcare. Patch to 1.26.1 immediately to protect your digital public infrastructure. |
| 5 | 2 | CVE-2026-92794 | Compromises unauthenticated access controls and token issuance in a default-deployed e-signature platform, directly impacting Digital Identity verification and Finance/Government contract workflows. | Default-configured e-signature platforms are leaking signer PII and valid download tokens without authentication. This TIER 2 flaw in OpenSign highlights how missing authorization in digital identity workflows can undermine legally binding contracts across finance and government sectors. |
| 4 | 2 | CVE-2026-19667 | Foundational DNS infrastructure (BIND 9) underpins all regulated sectors; unauthenticated remote DoS threatens availability of government, finance, and healthcare digital services. | DNS is the backbone of digital public infrastructure. This unauthenticated remote DoS in BIND 9 can crash resolvers with a single crafted response, threatening the availability of citizen, financial, and healthcare services. Patch immediately or implement redundancy. |
| 4 | 2 | CVE-2026-89783 | Foundational Linux kernel IPsec vulnerability impacting government, finance, and healthcare infrastructure relying on IPv6 security policies. | Linux kernel IPsec flaw (CVE-2026-89783) poses a Tier 2 risk to DPI stacks. While requiring specific IPv6/XFRM configs, it underscores the need to patch foundational infrastructure supporting critical public and regulated services. |
| 4 | 2 | CVE-2026-90049 | Foundational Linux kernel networking flaw affecting cloud and NFV infrastructure, posing transitive risk to all hosted DPI services. | A TIER 2 Linux kernel vulnerability in Open vSwitch + IPsec configurations enables unauthenticated RCE on cloud and telecom infrastructure. While niche, it underscores the critical need for timely kernel patching in foundational DPI hosting environments. |
| 4 | 2 | CVE-2026-92804 | Manages OAuth flows, credential storage, and API authentication for integrated services, positioning it as critical identity-adjacent infrastructure for regulated and public-sector digital ecosystems. | A TIER 2 SSRF in Nango exposes how unvalidated configuration in OAuth and token management platforms can lead to cloud credential theft and internal network mapping. Organizations relying on integration layers for digital identity and API authentication should enforce strict outbound URL policies and rotate exposed secrets immediately. |
| 3 | 2 | CVE-2026-20329 | Tier 2 critical vulnerability in Cisco Secure Firewall edge appliances, foundational general infrastructure explicitly linked to protecting public and enterprise network perimeters. | Critical CVSS 9.9 flaw in Cisco Secure Firewall ASA/FTD/FMC demands immediate patching. As foundational perimeter infrastructure for public and enterprise networks, unhandled exceptions could trigger widespread DoS or RCE with no workarounds available. |
| 3 | 2 | CVE-2026-20330 | Critical unauthenticated flaw in Cisco Secure Firewall impacts general infrastructure foundational to all regulated and public digital services. | A CVSS 9.9 vulnerability in Cisco Secure Firewall appliances requires immediate patching, as unauthenticated exploitation could compromise the network perimeters protecting critical public and regulated services. No workarounds exist—upgrade to fixed releases now. |
| 3 | 2 | CVE-2026-20333 | TIER 2 logic flaw in Cisco ASA/FTD edge firewalls, foundational network infrastructure that secures perimeter access for regulated and public digital services. | Critical edge firewall vulnerabilities demand proactive patching: CVE-2026-20333 (CVSS 8.8) affects Cisco ASA/FTD deployments, reminding DPI operators that perimeter security is only as strong as its underlying logic. Prioritize your 30–60 day patch cycle to protect public-facing infrastructure. |
| 3 | 2 | CVE-2026-77692 | Foundational DNS infrastructure (BIND 9) underpins national digital services; DoS risk to public-facing DoH resolvers used by government/enterprise. | DNS is the backbone of digital public infrastructure. A single crafted DoH request can crash BIND 9 resolvers, highlighting the need to patch foundational infrastructure or disable unused DoH endpoints. |
| 3 | 2 | CVE-2026-82399 | Foundational DNS infrastructure vulnerability threatening resolver availability across national digital public infrastructure and regulated sectors. | CoreDNS DoS vulnerability (CVE-2026-82399) threatens encrypted DNS resolvers used in national digital infrastructure. While default configs are safe, explicitly configured DoH/DoQ endpoints face OOM risks—patch to v1.14.7 or disable unused transports. |
| 3 | 2 | CVE-2026-89775 | Foundational Linux KVM hypervisor flaw impacting multi-tenant cloud infrastructure underpinning all DPI sectors, though limited to arm64 hosts with nested virtualization enabled. | Critical KVM guest-escape vulnerability highlights the hidden risks in foundational cloud infrastructure. While requiring a non-default configuration, it underscores the need for strict hypervisor hardening across government and enterprise digital services. |
| 2 | 2 | CVE-2026-70416 | Foundational enterprise object storage that may underpin data lakes and backups for Healthcare, Finance, and Government deployments. | Unauthenticated RCE in Dell ObjectScale (CVE-2026-70416) threatens internal data lakes and backup clusters. Public sector and regulated enterprises should enforce strict network segmentation and patch promptly to protect critical data infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-14871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-1168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19248.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19666.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20222.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20234.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20284.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20323.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20341.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20342.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20344.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2380.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42784.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62997.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71180.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73435.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73438.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73439.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73447.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73461.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73468.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75516.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76420.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77406.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77407.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77409.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81634.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81875.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86106.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86109.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86359.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86831.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87024.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88263.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89792.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89815.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89823.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89836.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89838.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89854.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89899.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89928.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89960.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89973.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89980.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89986.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89988.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89990.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89992.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89997.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90001.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90011.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90012.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90016.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90022.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90027.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90038.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92125.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92128.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92466.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92468.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92597.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92599.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92604.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92605.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92616.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92796.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92811.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-73462.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-77410.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-89883.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-89947.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-90014.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-92625.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-92626.md` — heuristic TIER 3/4
