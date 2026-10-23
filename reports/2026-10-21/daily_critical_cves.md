# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-22 23:53:03Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-21`
- **Included count:** 26

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-103090 | Directly compromises Zero Trust identity infrastructure by enabling unauthenticated theft of Biscuit tokens and OIDC enrollment credentials, impacting Digital Identity management. | A new TIER 2 vulnerability in Google’s OSS Agent Mesh exposes a critical flaw in Zero Trust identity management: unauthenticated attackers can steal valid Biscuit tokens and manipulate access policies on internet-facing control planes. Organizations deploying agent mesh or OIDC-based identity fabrics should prioritize patching to v0.1.0-alpha.9 to prevent credential theft and routing disruption. |
| 5 | 1 | CVE-2026-109618 | Foundational web runtime (PHP) with active wild exploitation underpins government, finance, healthcare, and digital identity services globally. | Critical unauthenticated RCE in PHP is actively exploited in the wild, threatening the foundational web layer of government, finance, and healthcare services. Immediate patching is required as default configurations offer no protection. |
| 5 | 1 | CVE-2026-109619 | Foundational PHP runtime vulnerability enabling unauthenticated RCE across government portals, financial services, and identity management systems. | Critical PHP core flaw (CVE-2026-109619) is actively exploited in the wild with zero default barriers, threatening the foundational web infrastructure of government, finance, and digital identity services. Immediate patching is essential for all DPI operators. |
| 5 | 2 | CVE-2026-112212 | Directly compromises OAuth/OIDC discovery endpoints in GitLab, a widely deployed IdP for enterprise and government digital identity federation. | GitLab’s OAuth/OIDC discovery endpoints are vulnerable to cache poisoning, enabling attackers to hijack SSO flows and intercept credentials. Organizations using GitLab as an identity provider for government or enterprise services should prioritize patching to protect their digital identity infrastructure. |
| 5 | 2 | CVE-2026-91403 | Foundational Java SE runtime flaw in TLS/SSL handling poses systemic risk to Finance, Government, Healthcare, and Digital Identity services globally. | Critical unauthenticated flaw in Oracle Java SE’s TLS stack demands immediate patching across regulated sectors. As a foundational runtime, its compromise threatens the integrity of national digital infrastructure, from banking APIs to citizen services. |
| 5 | 2 | CVE-2026-94300 | Foundational DNS infrastructure (BIND 9) with RCE impacts availability and integrity across Government, Finance, Healthcare, and Digital Identity sectors. | Critical DNS infrastructure at risk: BIND 9 RCE (CVE-2026-94300) threatens the backbone of public and regulated digital services. Patch immediately to protect government, finance, and healthcare DNS resolvers from memory corruption attacks. |
| 4 | 2 | CVE-2026-111811 | Foundational CDN/reverse proxy infrastructure widely deployed across government and finance edge services; unauthenticated cache manipulation poses high impact if misconfigured. | Apache Traffic Server’s experimental cache plugin exposes a critical unauthenticated manipulation flaw (CVE-2026-111811). While disabled by default, misconfigured edge proxies in government and finance sectors could face cache poisoning or data exfiltration—verify your plugin configs and patch now. |
| 4 | 2 | CVE-2026-111814 | Critical mTLS authentication bypass in Apache Traffic Server, a foundational API gateway widely deployed across Finance, Government, and Healthcare digital services. | API gateways and reverse proxies form the secure edge for regulated public and financial services. This TIER 2 flaw in Apache Traffic Server demonstrates how default session-sharing can undermine mTLS controls, prompting DPI operators to audit multi-certificate setups and apply patches. |
| 4 | 2 | CVE-2026-111815 | Foundational edge proxy flaw impacting mTLS authentication across Digital Identity, Finance, Healthcare, and Government deployments. | Apache Traffic Server’s TLS session resumption flaw (CVE-2026-111815) bypasses client certificate checks across virtual hosts, posing a targeted risk to DPI sectors relying on mTLS for secure edge access. Patch or disable session resumption to protect regulated endpoints. |
| 4 | 2 | CVE-2026-114045 | Foundational remote desktop/VDI infrastructure (FreeRDP) with RCE impact, explicitly relevant to Government and General Infrastructure sectors for secure administrative access. | FreeRDP’s server-side audio channel flaw enables RCE in VDI and remote desktop backends widely used by government and enterprise IT. While authentication limits mass exploitation, public-sector remote access deployments should prioritize patching to 3.32.1+ or disable the rdpsnd channel. |
| 4 | 2 | CVE-2026-114108 | Finance sector relevance: unauthenticated RCE in an AI trading agent exposes broker tokens, trading strategies, and financial automation infrastructure. | AI-driven trading agents are becoming critical financial infrastructure, but default auth bypasses can hand attackers root access to broker tokens and trading strategies. Patching and enforcing API keys is essential for secure financial automation. |
| 4 | 2 | CVE-2026-114123 | Default public Azure deployments of the D365 Finance & Operations MCP server leak security roles and business logic without authentication, directly impacting enterprise financial systems. | Default public deployments of the D365 Finance & Operations MCP server are leaking security roles and business logic without authentication. Finance and operations teams should verify API key enforcement and network restrictions on Azure App Services immediately. |
| 4 | 2 | CVE-2026-89035 | TIER 2 session token replay in MikroTik RouterOS WebFig undermines foundational edge networking infrastructure widely deployed in government and ISP environments, threatening the availability of dependent digital public services. | Edge routers are the gatekeepers of digital public infrastructure. A new TIER 2 flaw in MikroTik RouterOS allows session token replay for persistent admin access, highlighting why securing perimeter management interfaces is critical for government and ISP networks. Patch or restrict WebFig access now. |
| 4 | 2 | CVE-2026-96888 | Foundational DNS infrastructure (BIND 9) underpinning all DPI sectors; DoS risk to public-facing resolvers used by government, finance, and healthcare services. | DNS remains the backbone of digital public infrastructure. This TIER 2 BIND 9 DoS highlights how even niche configurations can threaten the availability of government, healthcare, and financial services relying on public resolvers. Patch or audit your settings now. |
| 3 | 2 | CVE-2025-55702 | Tier 2 HTTP request smuggling in Apache Traffic Server bypasses front-end proxy security controls, impacting foundational infrastructure that underpins regulated enterprise and public services. | Proxy bypass vulnerabilities like CVE-2025-55702 in Apache Traffic Server highlight the fragility of front-end security controls in multi-proxy architectures. For DPI operators, patching reverse proxies and hardening connection pooling remains critical to preventing WAF evasion and session hijacking. |
| 3 | 2 | CVE-2026-110803 | Tier 2 unauthenticated DoS in a foundational Java web framework widely deployed for public-facing portals across government, healthcare, and finance sectors. | A single malformed request can exhaust thread pools and crash public-facing Vaadin portals. Regulated organizations should patch or filter v-uiId parameters immediately to prevent trivial, unauthenticated denial-of-service attacks. |
| 3 | 2 | CVE-2026-111813 | TIER 2 critical RCE in core reverse proxy infrastructure, relevant to DPI as it underpins public-facing and regulated digital services. | Even with configuration barriers, critical RCE in Apache Traffic Server’s experimental plugin poses a tangible risk to public-facing proxy layers. DPI teams should verify plugin usage and patch to protect citizen and enterprise services. |
| 3 | 2 | CVE-2026-114106 | Finance sector relevance: unauthenticated path traversal in an algorithmic trading agent exposes trading credentials and API keys, directly impacting quantitative finance operations. | AI-driven trading tools are expanding the attack surface for financial operations. This TIER 2 flaw shows how unauthenticated LLM agent APIs can leak critical trading credentials and API keys, underscoring the need for strict sandboxing and network segmentation in quant finance deployments. |
| 3 | 2 | CVE-2026-114489 | Tier 2 missing authorization in hMailServer admin APIs breaks multi-tenant email isolation, impacting foundational communication infrastructure across regulated sectors. | Email servers are the backbone of institutional communication. This Tier 2 flaw in hMailServer allows authenticated admins to bypass tenant boundaries, highlighting the critical need for strict API authorization in shared infrastructure. |
| 3 | 2 | CVE-2026-19630 | Foundational DNS infrastructure supporting all regulated/public digital services; unauthenticated DoS risks widespread disruption across government, finance, and healthcare networks. | DNS is the silent backbone of digital public infrastructure. This Tier 2 BIND 9 flaw enables unauthenticated resource exhaustion on widely deployed resolvers, threatening the availability of citizen-facing and regulated enterprise services. Immediate patching is critical to maintain service continuity. |
| 3 | 2 | CVE-2026-76290 | General infrastructure (security analytics/log management) widely deployed in government and regulated sectors; DoS could disrupt critical compliance monitoring and security operations. | Splunk Enterprise DoS (CVE-2026-76290) poses a silent risk to government and regulated sector security operations. While the vulnerable Edge Processor is off by default, enabled instances face unauthenticated resource exhaustion that could blind critical log monitoring and compliance pipelines. Patch or verify your configuration. |
| 3 | 2 | CVE-2026-82819 | Enterprise FTP platform explicitly deployed across Finance, Healthcare, and Government for compliant document exchange, making credential leakage a cross-sector regulated infrastructure risk. | Internet-facing enterprise FTP servers in regulated sectors remain prime targets for NTLM hash harvesting, even with authentication barriers. Patching Cerberus FTP Server is critical to protect cross-sector compliant file transfers from lateral movement risks. |
| 3 | 2 | CVE-2026-96640 | Foundational Python imaging library used across regulated web/document pipelines; DoS risk to public-facing services processing untrusted PDFs. | A TIER 2 DoS in Python's Pillow library shows how a single backend dependency can impact healthcare, finance, and government web services. Patch to 13.0.0+ or restrict append=True on untrusted uploads to protect your public-facing APIs. |
| 3 | 2 | CVE-2026-97206 | Core DNS naming infrastructure underpinning all digital sectors; DoS risk to recursive resolvers requires patching or disabling non-default DoQ. | Core DNS resolvers power every regulated digital service. This Tier 2 Unbound DoS flaw shows why niche protocol configs (DoQ) must be hardened or disabled to protect foundational naming infrastructure. |
| 2 | 2 | CVE-2026-114243 | Unauthenticated SQLi in an insurance management system exposes policyholder PII and financial records, aligning with the Finance sector. | Niche insurance platforms are not immune to critical flaws: this unauthenticated SQLi allows full database extraction without credentials. Financial data handlers must enforce prepared statements and strict session termination. |
| 2 | 2 | CVE-2026-114245 | Unauthenticated admin creation in an open-source insurance management system exposes financial and policy data, aligning with the Finance sector. | A niche open-source insurance app lacks basic auth checks, allowing attackers to spawn admin accounts and access financial records. Even demo tools handling sector data need baseline security. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-71437.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110744.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110938.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112381.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114055.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114063.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114067.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114085.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114097.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114109.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114135.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114137.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114140.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114143.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114144.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114391.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114396.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114476.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20291.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76291.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76473.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76474.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76475.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76476.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76477.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76478.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76479.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76481.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76491.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76495.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76496.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82230.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92206.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96642.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-76288.md` — heuristic TIER 3/4
