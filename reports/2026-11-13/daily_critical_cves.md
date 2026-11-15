# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-15 03:46:55Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-13`
- **Included count:** 38

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-107412 | Directly impacts Citrix NetScaler AAA virtual servers, a core Digital Identity and remote access component widely deployed across government, healthcare, and finance sectors. | Unauthenticated memory overflow in Citrix NetScaler Gateway/AAA could crash critical remote access and identity infrastructure. With no wild exploitation yet, now is the time to patch before attackers target government and enterprise AAA deployments. |
| 5 | 2 | CVE-2026-107413 | Directly impacts SAML-based SSO authentication availability on widely deployed enterprise gateways, affecting Digital Identity, Government, Healthcare, and Finance sectors. | A TIER 2 heap overflow in Citrix NetScaler’s SAML module can crash remote access gateways, disrupting SSO workflows for government, healthcare, and finance. Patch or restrict SAML endpoints to keep critical identity infrastructure online. |
| 5 | 2 | CVE-2026-126451 | Stored XSS in OpenEMR patient portals enables PHI exfiltration and staff session hijack, directly impacting healthcare digital infrastructure and HIPAA compliance. | Healthcare CISOs: OpenEMR's stored XSS flaw lets patients inject scripts that hijack clinician sessions and steal PHI. Patch to 8.5.0 now to protect clinical workflows and regulatory compliance. |
| 5 | 2 | CVE-2026-126487 | Healthcare sector: Authorization bypass in widely deployed OpenEMR EHR system undermines HIPAA audit compliance and clinical data security. | A Tier 2 vulnerability in OpenEMR lets low-privilege users disable audit logs and weaken security controls, posing a direct threat to HIPAA compliance and patient data integrity in healthcare networks. |
| 5 | 2 | CVE-2026-126488 | Healthcare sector: SQL injection in OpenEMR patient portal allows authenticated users to exfiltrate full database including PHI and staff hashes. | OpenEMR patient portal SQL injection (CVE-2026-126488) lets authenticated patients bypass isolation and dump entire EHR databases, including PHI and admin hashes. Healthcare providers must patch to 8.5.0+ immediately to protect clinical data and staff credentials. |
| 5 | 2 | CVE-2026-129110 | Unauthenticated RCE in sysPass, a centralized credential vault, directly threatens Digital Identity workflows and institutional access controls across Government, Finance, and Healthcare. | A critical, unauthenticated RCE in sysPass could hand attackers full control over institutional password vaults, bypassing authentication and compromising downstream Digital Identity services. Organizations relying on self-hosted credential managers should verify network segmentation and consider migrating to actively maintained alternatives. |
| 5 | 2 | CVE-2026-59074 | JWT signature bypass in Edito CMS enables authenticated privilege escalation to admin, directly impacting Digital Identity, Finance (e-commerce/B2B), and Government (citizen portals) deployments. | A missing JWT signature check in Edito CMS lets low-privilege users forge admin sessions, highlighting how fragile token validation can undermine digital identity, e-commerce, and government portals. Patching and strict session monitoring are critical for regulated deployments. |
| 4 | 2 | CVE-2024-58406 | Widely deployed across Chinese government agencies and state-owned enterprises; unauthenticated path traversal enables credential theft and lateral movement in public-sector OA systems. | Active exploitation of a path traversal flaw in Huatian OA8000 highlights risks to government and public-sector digital infrastructure. Unauthenticated access to internal office systems can quickly escalate to credential theft and deeper compromise. |
| 4 | 2 | CVE-2026-102612 | TIER 2 authentication bypass in BACnet/SC building automation stacks impacts Healthcare and Government facility security by allowing unauthenticated mesh access to critical HVAC and life-safety controls. | Building automation isn't just about comfort—it's critical infrastructure. A TIER 2 flaw in the BACnet/SC stack lets attackers bypass mTLS and join hospital & government facility networks unauthenticated. Patch your OT hubs before physical controls become a liability. |
| 4 | 2 | CVE-2026-107407 | Citrix NetScaler ADC/Gateway is a foundational IdAM and secure access platform across Digital Identity, Finance, Government, and Healthcare; SMPP DoS risk impacts regulated messaging gateways. | A critical memory overflow in Citrix NetScaler ADC/Gateway (CVE-2026-107407) can crash appliances processing SMPP traffic. Though it requires a specific load-balancing configuration, the flaw highlights the importance of patch discipline and config hardening for Digital Identity and regulated sector infrastructure. |
| 4 | 2 | CVE-2026-107408 | Critical unauthenticated DoS in Citrix NetScaler DNS/DoH edge components, directly impacting availability of Finance and Government citizen/banking portals. | Unauthenticated memory corruption in Citrix NetScaler’s DNS/DoH stack poses immediate availability risks to public-facing banking and government portals. Patching is the only mitigation for this Tier 2 edge infrastructure flaw. |
| 4 | 2 | CVE-2026-107409 | Foundational enterprise load balancer/gateway explicitly underpins Finance, Government, and Healthcare digital infrastructure, though impact is limited to explicitly configured DoH deployments. | Citrix NetScaler ADC/Gateway faces a critical DoS risk via DNS-over-HTTPS processing. While the feature isn't default, regulated sectors relying on NetScaler for secure access and traffic management should verify configurations and patch immediately. |
| 4 | 2 | CVE-2026-107411 | Critical edge infrastructure (Citrix NetScaler) widely deployed across government, finance, and healthcare DPI portals; unauthenticated DoS risk to public-facing access layers. | Citrix NetScaler ADC/Gateway faces a TIER 2 unauthenticated DoS flaw in its RTSP ALG component. While impact is availability-only, the appliance underpins many government and financial public portals—verify if RTSP ALG is enabled and patch promptly. |
| 4 | 2 | CVE-2026-107415 | Impacts foundational Digital Identity and secure access gateways (Citrix NetScaler) widely deployed in Government and Finance for citizen/customer MFA and SSO, risking critical service disruption. | A critical memory overflow in Citrix NetScaler’s Email OTP module could disrupt MFA and secure access gateways for government and financial services. While requiring a specific configuration, the unauthenticated DoS risk underscores the need to patch foundational identity infrastructure promptly. |
| 4 | 2 | CVE-2026-111334 | Critical unauthenticated DoS in Citrix NetScaler Gateway EPA service, widely deployed as foundational edge infrastructure for Government, Finance, and Digital Identity remote access portals. | Citrix NetScaler ADC/Gateway faces a critical unauthenticated DoS vulnerability (CVE-2026-111334) in its Endpoint Analysis service. While requiring EPA configuration, this flaw threatens the availability of government and financial remote access portals—patching and temporary EPA disablement are strongly advised. |
| 4 | 2 | CVE-2026-111337 | Foundational edge infrastructure (Citrix NetScaler) widely deployed by government and financial institutions for citizen portals and secure access; DoS directly threatens critical public and financial service continuity. | Citrix NetScaler ADC/Gateway faces a TIER 2 DoS vulnerability that could knock out internet-facing citizen portals and financial services. Patching is critical for government and enterprise edge infrastructure to maintain service continuity. |
| 4 | 2 | CVE-2026-111341 | Impacts client-certificate authentication on widely deployed Citrix NetScaler edge appliances, disrupting remote access and identity services for government, finance, and healthcare sectors. | A TIER 2 buffer overflow in Citrix NetScaler’s client-certificate authentication module could knock out remote access for regulated sectors. While it requires a non-default config, any DoS on identity edge infrastructure demands immediate patching and configuration review. |
| 4 | 2 | CVE-2026-111342 | Directly impacts LDAP authentication and remote access gateways widely deployed across Digital Identity, Government, Finance, and Healthcare sectors, risking disruption to critical public and regulated services. | A TIER 2 buffer overflow in Citrix NetScaler’s LDAP module could knock out remote access for regulated sectors. With NetScaler Gateway sitting at the edge of government, healthcare, and financial networks, this unauthenticated DoS threat demands immediate patching to protect citizen and patient access channels. |
| 4 | 2 | CVE-2026-120864 | Critical unauthenticated DoS in Citrix NetScaler ADC/Gateway, foundational remote-access infrastructure explicitly tied to Government, Finance, and Healthcare deployments. | An unauthenticated remote DoS in Citrix NetScaler gateways threatens the backbone of secure remote access for regulated sectors. With no configuration workarounds available, Government, Finance, and Healthcare IT teams must prioritize firmware upgrades to maintain critical perimeter continuity. |
| 4 | 2 | CVE-2026-120865 | TIER 2 DoS in Citrix NetScaler ADC/Gateway QUIC handler impacts Government, Finance, and Healthcare sectors reliant on the platform for secure citizen portals, banking gateways, and telemedicine access. | Citrix NetScaler ADC/Gateway faces a TIER 2 HTTP/3 QUIC overflow risk that could disrupt critical public and financial services. While disabled by default, organizations with explicit QUIC configurations should prioritize patching to maintain availability for citizen and patient portals. |
| 4 | 2 | CVE-2026-120867 | TIER 2 unauthenticated DoS in Citrix NetScaler ADC/Gateway threatens availability of internet-facing edge infrastructure critical to Government and Finance digital services. | Citrix NetScaler ADC/Gateway faces a TIER 2 memory overflow (CVE-2026-120867) that can crash internet-facing SSL/TLS termination. Government and financial institutions relying on this edge infrastructure for remote access and public portals should prioritize patching to maintain service availability. |
| 4 | 2 | CVE-2026-124679 | General infrastructure explicitly tied to Finance, Healthcare, and Government edge security, posing authentication bypass risks in regulated API deployments. | Apache APISIX’s authentication bypass (CVE-2026-124679) shows how misconfigured API gateways can undermine edge security for finance, healthcare, and government services. DPI operators should harden plugin settings and patch to 3.20.0 to protect regulated API traffic. |
| 4 | 2 | CVE-2026-126091 | Healthcare sector: unauthenticated exposure of patient PII and OAuth credentials in a cloud dental practice management platform. | Unauthenticated access to dental practice portals is leaking patient PII and OAuth credentials. Healthcare SaaS providers must secure API responses to prevent mass data scraping and regulatory breaches. |
| 4 | 2 | CVE-2026-126429 | Directly impacts widely deployed open-source Electronic Medical Records (EMR) systems in healthcare, risking PHI and credential theft via patient portals. | Healthcare providers running OpenEMR must patch immediately: a new TIER 2 vulnerability allows authenticated patients to exfiltrate database credentials and OAuth keys via the patient portal's PDF renderer. |
| 4 | 2 | CVE-2026-126454 | TIER 2 flaw in OpenEMR EHR enables TOTP brute-force, compromising MFA and risking PHI exposure in healthcare deployments. | DPI Watch: OpenEMR (CVE-2026-126454) lacks MFA rate limiting, allowing brute-force attacks on healthcare EHR accounts. Clinics must patch to 8.5.0 to protect patient records. |
| 4 | 2 | CVE-2026-127090 | Directly impacts Digital Identity by bypassing SSH public key authentication and breaking account-bound authorization in enterprise remote access and CI/CD environments. | A TIER 2 flaw in Jadaptive Maverick SSH servers lets attackers pivot between user accounts by exploiting cached key authorization. For DPI and enterprise infra, this underscores why strict credential binding and patching SSH gateways remain critical for identity security. |
| 4 | 2 | CVE-2026-127278 | Directly impacts Digital Identity infrastructure by exposing an unauthenticated authentication bypass in an agent identity registry that manages JWT sessions and OIDC/SAML anchoring. | A trivial authentication flaw in an emerging agent identity registry returns SMS codes in plain HTTP responses, enabling instant account takeover. For DPI architects, this underscores the critical need to enforce OIDC/SAML anchoring and network segmentation in identity lifecycle services. |
| 4 | 2 | CVE-2026-127279 | Implements national AI agent identity standards (GB/Z 185) for trusted registration and access control, positioning it as foundational digital identity infrastructure for government and regulated AI ecosystems. | Unauthenticated access to a national-standard AI agent identity server could compromise trusted registration and internal credentials. As AI interconnection becomes critical digital infrastructure, securing identity management endpoints is essential for government and enterprise DPI resilience. |
| 4 | 2 | CVE-2026-128041 | TIER 2 stored XSS in OpenMage e-commerce platform impacts the Finance sector by risking payment data, customer accounts, and transaction integrity. | E-commerce platforms handling payments and customer accounts face a TIER 2 stored XSS risk in OpenMage. While RSS feeds are disabled by default, admins enabling them could face account takeover and financial data exposure. Patch or disable RSS feeds to protect transaction integrity. |
| 4 | 2 | CVE-2026-82504 | Unauthenticated RCE in an enterprise IPTV platform explicitly deployed in government and military classified networks. | Critical unauthenticated RCE in VITEC EZ TV Platform Server poses a direct risk to government and military broadcast infrastructure, underscoring the need for strict network segmentation and timely patching in classified environments. |
| 3 | 2 | CVE-2026-107410 | TIER 2 unauthenticated DoS in Citrix NetScaler ADC/Gateway, a foundational public-facing edge proxy critical for regulated and citizen-facing digital services. | Citrix NetScaler ADC/Gateway faces a TIER 2 heap overflow risk via a niche PUSH protocol configuration. While not default, this edge proxy underpins many public-facing government and enterprise portals—audit active PUSH LB servers and apply patches promptly. |
| 3 | 2 | CVE-2026-123975 | Pre-auth DoS in Grid Community Toolkit disrupts federated research and government HPC infrastructure, impacting critical scientific and civic data processing. | A pre-authentication DoS flaw in the Grid Community Toolkit threatens the availability of federated research and government HPC ecosystems. Timely patching is critical to safeguard national scientific and civic data processing workloads. |
| 3 | 2 | CVE-2026-124680 | Foundational API gateway authorization bypass impacting edge routing and access control in regulated enterprise and public-sector deployments. | Apache APISIX users should patch CVE-2026-124680 to prevent unauthenticated access to protected APIs. This path normalization flaw highlights the critical need for strict routing configurations in public-facing DPI edge infrastructure. |
| 3 | 2 | CVE-2026-128049 | Finance sector relevance: CSRF in Magento LTS OAuth flow enables persistent API token theft, risking unauthorized access to customer financial data and transaction records. | E-commerce platforms handling payments and customer data face a new Tier 2 risk: a CSRF flaw in Magento LTS OAuth could let attackers steal persistent API tokens. Retailers and finance-facing services should audit OAuth consumers and restrict admin access immediately. |
| 3 | 2 | CVE-2026-129180 | Unauthenticated SQLi in a visitor management system commonly deployed in government buildings and public facilities, risking access logs and credential data. | Public-facing visitor management portals in government and corporate facilities face high risk from unauthenticated SQL injection. Patching and WAF rules are critical to protect access logs and prevent data breaches. |
| 3 | 2 | CVE-2026-62976 | Impacts building automation infrastructure critical to healthcare facilities and government buildings, risking HVAC and life-safety system availability. | A TIER 2 vulnerability in the BACnet protocol stack could disrupt critical building automation systems, posing availability risks to hospital life-safety infrastructure and public sector facilities. Patching and network segmentation are key mitigations. |
| 3 | 2 | CVE-2026-97692 | Unauthenticated RCE in BACnet/SC building automation stacks threatens operational continuity and physical security across government, healthcare, and financial facilities. | Building automation isn't just about HVAC—it's critical infrastructure. This unauthenticated RCE in BACnet/SC stacks highlights how OT vulnerabilities can cascade into physical security and operational risks for public and regulated facilities. Patch and segment your OT networks. |
| 2 | 2 | CVE-2026-100403 | TIER 2 unauthenticated DoS in BACnet/SC hubs disrupts building automation in public and critical facilities, impacting OT infrastructure availability. | Facility management relies on OT stacks like BACnet/SC, which now face a TIER 2 unauthenticated DoS risk. Public buildings and critical infrastructure must prioritize patching and network segmentation to prevent HVAC and access control outages. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-43867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-43874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103813.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107414.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107522.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111545.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111547.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112181.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120221.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126280.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126282.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126283.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126308.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126312.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126391.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126401.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126403.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126415.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126416.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126434.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126436.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126437.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126443.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126449.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126457.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126458.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126461.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126465.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126466.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126468.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126470.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126472.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126473.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126478.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126479.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126480.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126481.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126482.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126483.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126491.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126982.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127073.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127078.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127079.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127080.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127102.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127214.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128040.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128081.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-128790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129167.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63079.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63167.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71531.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95379.md` — heuristic TIER 3/4
