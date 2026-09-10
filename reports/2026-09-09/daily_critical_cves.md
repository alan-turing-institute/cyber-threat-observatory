# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-10 17:06:10Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-09`
- **Included count:** 11

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-80172 | Critical unauthenticated flaw in Dell's ZTNA gateway enables indefinite administrative token generation, directly compromising Digital Identity and access management infrastructure. | A critical flaw in Dell Secure Connect Gateway lets attackers bypass Zero Trust controls and forge admin tokens without credentials. For organizations relying on ZTNA for secure remote access, this underscores the urgent need to patch identity-aware edge gateways before they become a backdoor into regulated networks. |
| 4 | 2 | CVE-2026-67403 | Finance sector: critical cross-tenant authorization bypass in a SaaS accounts receivable platform threatens financial data integrity and regulatory compliance. | A critical authorization flaw in Sage AR Automation allows authenticated users to bypass tenant boundaries, exposing sensitive financial records across organizations. For finance and public sector teams relying on SaaS accounting tools, this underscores the urgent need for strict API governance and tenant isolation controls. |
| 4 | 2 | CVE-2026-79322 | Unauthenticated SQLi in a widely deployed Magento 2 extension exposes customer PII and payment/transaction data, directly impacting Finance and e-commerce infrastructure. | A verified PoC for an unauthenticated SQL injection in a popular Magento 2 extension underscores the risks of internet-exposed e-commerce storefronts. Finance and retail operators should prioritize patching or WAF rules to safeguard customer data and payment infrastructure. |
| 4 | 2 | CVE-2026-79635 | Unauthenticated SSRF in a public-facing ZTNA gateway poses direct risk to foundational remote access infrastructure commonly deployed by government and finance sectors. | Zero Trust Network Access (ZTNA) gateways are critical edge infrastructure for secure remote access in regulated sectors. This unauthenticated SSRF in Dell SCG 5.0 requires immediate patching to prevent internal network pivoting and metadata exposure. |
| 4 | 2 | CVE-2026-79636 | Unauthenticated remote access bypass in Dell SCG ZTNA gateway undermines Digital Identity perimeter controls and zero-trust session validation. | Dell's Secure Connect Gateway faces a TIER 2 certificate validation flaw that lets unauthenticated attackers bypass zero-trust controls. Patching edge identity infrastructure is critical to protect remote access perimeters. |
| 4 | 2 | CVE-2026-79641 | Foundational ZTNA edge gateway vulnerability impacting secure remote access for government and finance deployments, with no available workarounds. | A TIER 2 command injection in Dell’s Secure Connect Gateway threatens Zero Trust access for government and financial institutions. With no mitigations available, patching this internet-facing edge appliance is urgent to prevent lateral movement and service disruption. |
| 4 | 2 | CVE-2026-85102 | Critical unauthenticated RCE in widely deployed enterprise VPN gateways, explicitly noted as foundational infrastructure for Government and Finance perimeter security. | Unauthenticated RCE in Check Point VPN gateways poses immediate perimeter risk to government and financial networks. Patch urgently or restrict UDP 500/4500 access to prevent initial access attacks. |
| 4 | 2 | CVE-2026-87016 | Digital Identity sector: OAuth/SCIM identity resolution bypass enables full session takeover via SQL wildcard injection in self-hosted AI platforms. | CVE-2026-87016 exposes a critical identity resolution flaw in Open WebUI where OAuth/SCIM subject claims containing SQL wildcards can hijack admin sessions. Teams deploying self-hosted AI platforms with custom IdAM integrations should audit claim mappings and patch to v0.11.1. |
| 3 | 2 | CVE-2026-79689 | Unauthenticated remote command injection in a default public-facing enterprise gateway with no workarounds, posing a direct pivot risk to underlying DPI services. | Dell Secure Connect Gateway faces a Tier 2 unauthenticated command injection flaw with zero available workarounds. As a default public-facing perimeter device, it demands immediate patching to protect the infrastructure underpinning critical digital services. |
| 3 | 2 | CVE-2026-80122 | Internet-facing ZTNA gateway vulnerability with no mitigations, directly impacting secure remote access architectures foundational to regulated and public-sector operations. | An unauthenticated bypass in Dell’s internet-facing ZTNA gateway (CVE-2026-80122) leaves remote access controls wide open with zero workarounds. A critical reminder for public and regulated sectors to prioritize edge security patching before exploitation scales. |
| 3 | 2 | CVE-2026-85103 | Tier 2 unauthenticated RCE in internet-facing Check Point VPN gateways; critical general infrastructure underpinning secure remote access for regulated and public-sector networks. | A CVSS 9.8, unauthenticated RCE in Check Point Quantum VPN gateways highlights the persistent risk to internet-exposed perimeter infrastructure. While no wild exploitation is confirmed, the pre-auth attack path on default deployments demands immediate LivePatch deployment for any organization relying on secure remote access. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-12855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15140.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15913.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18147.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-22590.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-23855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6485.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65181.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73769.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78482.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78491.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79617.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79696.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86746.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87021.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87023.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87072.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87500.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87514.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87542.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87604.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87925.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87998.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88069.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-22591.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-73786.md` — heuristic TIER 3/4
