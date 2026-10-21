# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-21 06:12:41Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-14`
- **Included count:** 66

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-101019 | Directly impacts SAML-based identity federation and SSO gateways (nginx-saml), enabling authentication bypass for expired or misdirected tokens in government, finance, and healthcare deployments. | A new TIER 2 vulnerability in NGINX's njs module could undermine SAML-based SSO gateways by allowing attackers to bypass token expiry and destination checks. Organizations relying on nginx-saml for public-facing identity federation should prioritize patching to protect critical authentication pipelines. |
| 5 | 1 | CVE-2026-110447 | Actively exploited unauthenticated RCE in Nextcloud's Collabora app directly threatens government and healthcare deployments relying on it for secure document management and patient record sharing. | Public sector and healthcare agencies running Nextcloud face immediate risk from a critical, actively exploited RCE in the Collabora Online app. Patching to v26.4.303+ is mandatory to prevent full server compromise and protect sensitive citizen and patient data. |
| 5 | 2 | CVE-2026-110862 | Digital Identity sector: critical authentication bypass in a core IdAM framework enabling unauthenticated account takeover via OAuth/Magic Link token confusion. | A critical flaw in the Better Auth framework allows attackers to hijack user sessions by exploiting default OAuth and Magic Link configurations. Organizations relying on modern identity stacks should patch immediately to prevent widespread account takeovers. |
| 5 | 2 | CVE-2026-110863 | Digital Identity: Compromises OIDC/SAML authentication and session management, enabling account takeover via flawed provider lookup logic. | A critical flaw in a popular SSO library allows attackers to hijack accounts by spoofing OIDC/SAML providers. Organizations relying on modern identity stacks should patch immediately to prevent session forgery and unauthorized access. |
| 5 | 2 | CVE-2026-16740 | Critical unauthenticated command injection in a widely deployed Turkish WAF/ADC, directly impacting Government and Finance digital infrastructure. | A critical missing-auth flaw in TR7’s ASP platform could bypass perimeter defenses across Turkish government and financial networks. With no active exploitation yet, immediate patching and strict management-plane segmentation are essential to protect national digital infrastructure. |
| 5 | 2 | CVE-2026-16741 | Unauthenticated RCE in widely deployed government and regulated-sector WAF/WAAP appliances enables critical security control bypass and infrastructure compromise. | Critical unauthenticated RCE in TR7 ASP WAF appliances threatens Turkish government and regulated sector infrastructure. Compromising these security controls allows attackers to bypass protections and pivot deeper into public digital services. |
| 5 | 2 | CVE-2026-89071 | LDAP injection in widely deployed enterprise MFT platform directly compromises authentication and directory sync, impacting Digital Identity, Government, Healthcare, and Finance sectors. | Progress MOVEit Transfer’s LDAP module faces a critical injection flaw that could bypass authentication and expose directory data across government, healthcare, and finance networks. Patching and strict credential controls are essential to protect digital identity infrastructure. |
| 4 | 2 | CVE-2026-0321 | Foundational perimeter firewall DoS vulnerability impacting availability across government, finance, and healthcare deployments. | Unauthenticated DoS in Palo Alto PAN-OS can force critical perimeter firewalls into maintenance mode, disrupting connectivity for regulated sectors. Patching is essential to maintain availability for government, financial, and healthcare digital services. |
| 4 | 2 | CVE-2026-0322 | General Infrastructure: foundational firewall stack critical to national digital operations and cross-sector regulated environments, with confirmed in-wild exploitation. | A confirmed in-wild RCE in Palo Alto PAN-OS firewalls (CVE-2026-0322) highlights the persistent risk to foundational network security. Even with internal-only defaults, this CISA-listed flaw reinforces why strict segmentation and admin MFA are non-negotiable for national digital infrastructure. |
| 4 | 2 | CVE-2026-101337 | Core DNS infrastructure vulnerability impacting national internet resilience and service availability across all DPI sectors. | DNS remains the backbone of digital public infrastructure. This TIER 2 vulnerability in NSD highlights how provisioning or supply-chain compromises can undermine national internet resilience, urging stricter zone file validation and timely patching. |
| 4 | 2 | CVE-2026-101341 | General infrastructure DNS server (NSD) critical for national naming resilience; compromise risks service disruption across government, finance, and healthcare DPI sectors. | Authoritative DNS servers like NSD underpin national naming resilience and critical public services. This TIER 2 RCE in zone file parsing highlights the need to secure provisioning pipelines, not just public-facing query interfaces. |
| 4 | 2 | CVE-2026-101940 | Foundational Juniper Junos routing infrastructure deployed across government, finance, and healthcare sectors faces targeted DoS risk, impacting availability of regulated digital services. | Juniper Junos routers underpin critical government and financial networks. This Tier 2 BGP vulnerability shows how specific routing features can become availability choke points for digital public infrastructure. Proactive patching and BGP hardening are key to maintaining service resilience. |
| 4 | 2 | CVE-2026-101948 | TIER 2 BGP routing daemon DoS in Juniper Junos OS, foundational networking infrastructure explicitly underpinning ISP backbones and government/financial network edges. | A TIER 2 vulnerability in Juniper Junos OS could crash core BGP routing daemons via crafted FlowSpec updates, threatening the stability of ISP backbones and critical government/financial network edges. Patching or disabling FlowSpec is essential for maintaining national routing infrastructure resilience. |
| 4 | 2 | CVE-2026-101954 | Foundational networking OS underpinning government and critical infrastructure backbones, enabling unauthenticated root compromise if web management is enabled. | Unauthenticated root access in Juniper Junos OS highlights the critical need to secure foundational network infrastructure that powers government and public services. Even with default-disabled web management, exposed edge devices face immediate takeover risks. |
| 4 | 2 | CVE-2026-101977 | Core routing infrastructure flaw causing persistent DoS that disrupts the foundational connectivity layer for all regulated and public digital services. | A TIER 2 vulnerability in Juniper Junos OS routing daemons can trigger persistent network blackholes via crafted BGP packets, underscoring the critical need to secure the core routing fabric that powers government, finance, and healthcare digital infrastructure. |
| 4 | 2 | CVE-2026-101997 | Critical SQL injection in Juniper SRX firewalls enables root RCE, directly impacting government and critical infrastructure network perimeters where these devices serve as foundational security choke points. | Juniper SRX firewalls face a critical SQL injection flaw (CVE-2026-101997) that can grant attackers root access to network perimeters. While requiring an optional security feed configuration, this vulnerability underscores the need for strict patch management and configuration audits across government and critical infrastructure deployments. |
| 4 | 2 | CVE-2026-102027 | Foundational routing infrastructure (Juniper Junos) underpinning government, finance, and healthcare networks; BGP DoS risks widespread service disruption across regulated sectors. | A Tier 2 BGP routing flaw in Juniper Junos OS could trigger widespread network outages across government and financial infrastructure. Patching edge routers and auditing eBGP peering is critical to maintain DPI backbone resilience. |
| 4 | 2 | CVE-2026-102062 | Critical perimeter firewall vulnerability impacting Finance and Government sectors, threatening digital public services and financial transaction integrity via unauthenticated root RCE. | Juniper SRX firewalls face a critical format string flaw that could grant attackers root access to perimeter defenses. While exploitation requires compromising a trusted threat feed server, Finance and Government agencies must patch immediately to protect critical digital infrastructure and citizen data. |
| 4 | 2 | CVE-2026-102064 | Foundational Juniper Junos OS routing daemon DoS impacts network availability across Government, Finance, Healthcare, and Digital Identity infrastructure. | Core network availability is the backbone of digital public infrastructure. This TIER 2 Juniper Junos OS routing daemon vulnerability highlights why proactive patching and BGP hardening remain critical for protecting government, financial, and healthcare edge networks. |
| 4 | 2 | CVE-2026-102065 | Foundational Juniper Junos OS networking stack underpins national digital backbones; BGP/SRv6 DoS threatens routing stability across regulated and public infrastructure. | Juniper Junos OS faces a Tier 2 DoS risk via SRv6 BGP routes that could disrupt national digital backbones. While requiring specific tunnel configs, it highlights the fragility of core routing infrastructure—patch and restrict BGP peers now. |
| 4 | 2 | CVE-2026-102174 | Impacts Juniper SRX VPN gateways and JIMS identity-publishing, directly affecting digital identity and secure remote access for government, finance, and healthcare networks. | A critical authenticated RCE in Juniper SRX VPN gateways highlights the risks in identity-publishing paths, reinforcing the need for MFA and strict access controls across government and financial remote-access infrastructure. |
| 4 | 2 | CVE-2026-102180 | TIER 2 remote DoS in Juniper Junos OS routing daemon impacts foundational network backbones supporting government, finance, and healthcare digital services. | Juniper Junos OS routers face a TIER 2 remote DoS risk via BGP telemetry streaming. While requiring a specific configuration, this vulnerability underscores the need to harden foundational network infrastructure underpinning critical public and regulated sector backbones. |
| 4 | 2 | CVE-2026-102182 | Critical unauthenticated RCE on internet-facing Juniper MX perimeter routers, foundational infrastructure for government, ISP, and enterprise networks. | Unauthenticated root RCE on Juniper MX edge routers poses a severe risk to government and enterprise network perimeters. With no workarounds available, immediate patching is critical to protect exposed IPsec VPN gateways. |
| 4 | 2 | CVE-2026-102460 | TIER 2 authorization bypass in Eclipse Vert.x Web impacts JWT/OAuth2 scope validation, directly affecting Digital Identity and public-sector API gateways relying on nested authentication handlers. | Scope-based access control is foundational to modern digital identity, but a new TIER 2 flaw in Eclipse Vert.x Web shows how nested routing can silently bypass JWT/OAuth2 constraints. Public sector and regulated API gateways should audit their authentication handler chains and patch immediately. |
| 4 | 2 | CVE-2026-104108 | Direct OIDC authentication bypass enabling account takeover via unverified claim manipulation, impacting Digital Identity and enterprise SSO boundaries. | Self-hosted file managers using OIDC SSO are vulnerable to admin takeover if IdP claims aren't strictly validated. This CVE highlights why immutable identity binding and verified claims are non-negotiable for enterprise and government digital infrastructure. |
| 4 | 2 | CVE-2026-104939 | Bypasses OAuth IdP validation in public-facing ingress controllers, directly impacting federated identity verification for digital public services. | A new TIER 2 flaw in F5 NGINX Ingress Controller allows attackers to skip OAuth authentication checks at the network edge. Teams managing federated identity for public or regulated services should audit externalAuth policies and apply patches to protect citizen and enterprise access layers. |
| 4 | 2 | CVE-2026-106931 | Host-based WAF privilege escalation actively exploited in the wild, directly threatening the integrity and availability of Government and public-sector web infrastructure. | Active exploitation of a local privilege escalation in a widely deployed host-based WAF underscores the critical need for patch management in public-sector infrastructure. Even post-compromise vectors can cascade into full system control, making timely updates essential for protecting digital public services. |
| 4 | 2 | CVE-2026-108065 | Unauthenticated SQLi in a B2B e-commerce platform handling payment processing and financial transactions, directly impacting the Finance sector. | Critical unauthenticated SQL injection in a widely deployed B2B e-commerce platform exposes payment processing and financial transaction data. Finance and wholesale distributors should immediately block the vulnerable SOAP endpoint to prevent data breaches and RCE. |
| 4 | 2 | CVE-2026-108071 | MFA bypass in TSplus Remote Access directly undermines digital identity and access controls, impacting government, finance, and healthcare remote operations. | A critical MFA bypass in TSplus Remote Access (CVE-2026-108071) turns stolen credentials into full system access, bypassing second-factor checks. Organizations relying on remote access gateways for secure digital identity must patch immediately and audit authentication logs. |
| 4 | 2 | CVE-2026-110765 | Directly impacts financial operations and payment reconciliation infrastructure by allowing unauthenticated forgery of billing webhooks, compromising accounting integrity and revenue tracking. | Unauthenticated attackers can forge payment webhooks in FlexPrice billing platforms, bypassing signature checks to manipulate invoices and trigger revenue leakage. A critical reminder for finance and accounting teams to enforce strict webhook validation and monitor unsigned payment callbacks. |
| 4 | 2 | CVE-2026-110864 | Directly impacts Digital Identity infrastructure by enabling authentication bypass and account takeover in a widely adopted OAuth/OIDC session management framework. | Modern identity frameworks power digital public services, but misconfigured OAuth proxies can turn convenience into critical account takeover risks. Ensure your IdAM deployments enforce dedicated secrets and database-backed state storage to protect citizen and enterprise accounts. |
| 4 | 2 | CVE-2026-14851 | Direct authorization bypass in a public-facing billing platform exposes customer PII, payment details, and transaction records, aligning with the Finance sector. | A critical authorization flaw in Copart’s public billing service allows unauthenticated access to customer invoices and payment data. For finance and regulated platforms, this underscores the urgent need to enforce strict access controls on document-serving endpoints and monitor for automated scraping. |
| 4 | 2 | CVE-2026-33795 | Foundational Juniper Junos OS routing flaw impacting BGP Prefix-SID, explicitly tied to national digital backbone stability and cross-sector network infrastructure. | A TIER 2 routing daemon vulnerability in Juniper Junos OS could disrupt BGP Prefix-SID services, threatening the availability of national digital backbones and regulated enterprise networks. Infrastructure teams should verify Prefix-SID configurations and apply vendor patches to maintain backbone resilience. |
| 4 | 2 | CVE-2026-55381 | Cross-tenant IDOR in a multi-tenant invoicing platform exposes sensitive financial records and pricing data, directly impacting Finance sector digital infrastructure. | Multi-tenant SaaS platforms handling invoices and payments face severe data leakage risks when authorization checks miss object-level scoping. This TIER 2 flaw in InvoiceShelf highlights why financial service providers must enforce strict tenant isolation and audit API access controls. |
| 4 | 2 | CVE-2026-55383 | Finance sector: cross-tenant financial document disclosure in public-facing invoicing platforms impacts payment operations and account confidentiality. | Unpatched InvoiceShelf instances face cross-tenant financial data leaks via token validation bypasses. Finance and public sector teams relying on self-hosted or SaaS invoicing should patch to 2.4.0 immediately to protect payment records and customer confidentiality. |
| 4 | 2 | CVE-2026-73790 | Remote unauthenticated DoS on HPE NonStop iTP WebServer, a mainframe platform widely deployed in critical Finance and Government transaction systems. | Unauthenticated remote DoS in HPE NonStop web servers threatens availability for banks and government agencies relying on legacy mainframe infrastructure. Prompt patching is critical to prevent service disruption in regulated sectors. |
| 4 | 2 | CVE-2026-76519 | Critical, exploited path traversal in Cisco Secure Email Gateway compromises foundational email security infrastructure widely deployed across government, finance, and healthcare sectors. | Unauthenticated root RCE in Cisco Secure Email Gateway is now actively exploited and on the CISA KEV catalog. Organizations in regulated sectors must patch immediately to protect critical email gateways from full OS takeover and lateral movement. |
| 4 | 2 | CVE-2026-79957 | IDOR in SaaS ITSM platform exposes cleartext passwords and user profiles, directly impacting Digital Identity and credential management for enterprise/government tenants. | A TIER 2 IDOR in a cloud-hosted ITSM platform allows authenticated users to harvest cleartext passwords across entire tenants. For DPI operators, this highlights the critical need for strict server-side authorization and MFA enforcement in cloud identity services. |
| 4 | 2 | CVE-2026-89067 | Enterprise MFT platform heavily deployed across Healthcare, Finance, and Government for regulated data exchanges; authentication bypass enables unauthorized access to sensitive transfers. | MOVEit Transfer remains a critical backbone for regulated data exchanges across healthcare, finance, and government. This TIER 2 authentication bypass highlights why patching internet-facing MFT portals is non-negotiable for DPI resilience. |
| 4 | 2 | CVE-2026-89070 | TIER 2 OIDC authentication bypass in Progress MOVEit Transfer, widely deployed across Healthcare, Finance, and Government for secure external data exchange. | A TIER 2 authentication bypass in Progress MOVEit Transfer’s OIDC module highlights the risks of token replay attacks in enterprise file transfer platforms. Widely used by healthcare, finance, and government agencies for secure data exchange, this flaw underscores the need for strict token lifecycle management and IdP logging in regulated environments. |
| 4 | 2 | CVE-2026-89072 | TIER 2 authorization bypass in Progress MOVEit Transfer, a widely deployed enterprise file transfer platform critical to Healthcare, Finance, Government, and Digital Identity data exchange workflows. | Progress MOVEit Transfer faces a TIER 2 authorization bypass (CVE-2026-89072) that could let low-privilege users access sensitive files. Given its widespread use in regulated sectors for secure partner exchanges, patching to 2025.1.6/2026.0.4 is critical for DPI resilience. |
| 4 | 2 | CVE-2026-89073 | Critical session persistence flaw in Progress MOVEit Transfer, a widely deployed enterprise MFT platform handling regulated data exchanges across public and private sectors. | Public-facing Managed File Transfer portals are prime targets for data exfiltration. CVE-2026-89073 extends stolen session lifespans indefinitely in Progress MOVEit, underscoring the need for strict token hygiene and proxy-level timeouts in regulated data pipelines. |
| 4 | 2 | CVE-2026-89076 | High-severity SQLi in Progress MOVEit Transfer, a general infrastructure platform widely deployed across regulated sectors for secure data exchange, posing significant data exfiltration and privilege escalation risks. | Secure file transfer platforms like Progress MOVEit Transfer are backbone infrastructure for regulated sectors. This TIER 2 SQL injection in the reporting module highlights why strict admin access controls and prompt patching are non-negotiable for protecting sensitive citizen, financial, and health data. |
| 4 | 2 | CVE-2026-89077 | Public-facing enterprise file transfer platform with authentication bypass, explicitly tied to regulated Healthcare, Finance, and Government data exchange workflows. | A high-severity authentication flaw in Progress MOVEit Transfer’s SFTP module could expose sensitive regulated data in transit. With public-facing deployments common across healthcare, finance, and government, prioritized patching is critical to prevent unauthorized file access and data breaches. |
| 3 | 2 | CVE-2026-101950 | Critical unauthenticated RCE/DoS in foundational edge firewalls (Juniper SRX) that secure public-facing digital services across regulated sectors. | A TIER 2 critical vulnerability in Juniper SRX firewalls could allow unauthenticated remote code execution on public-facing edge networks. While requiring a specific SD-WAN routing config, this heap overflow underscores the need to patch foundational security infrastructure protecting government, finance, and healthcare digital services. |
| 3 | 2 | CVE-2026-101952 | Tier 2 DoS in Juniper Junos OS routing daemon impacts foundational network transport underpinning telecom, enterprise, and public digital infrastructure. | Core routing resilience matters for DPI: a Tier 2 DoS in Juniper Junos OS can crash routing daemons and create network blackholes, highlighting the need for strict BGP validation and timely patching in public and regulated infrastructure backbones. |
| 3 | 2 | CVE-2026-101955 | General infrastructure edge firewall flaw enabling unauthenticated RCE/DoS, explicitly noted as impacting public-sector and regulated enterprise perimeters. | A critical buffer overflow in Juniper SRX firewalls allows unauthenticated RCE via malformed DNS packets when anti-spam inspection is active. Though disabled by default, public-sector and regulated network operators should audit UTM configurations and apply patches to secure critical perimeters. |
| 3 | 2 | CVE-2026-101961 | Core ISP/enterprise routing OS underpins connectivity for all DPI sectors; BGP daemon crash risks widespread network outages. | Foundational routing infrastructure remains a critical attack surface. CVE-2026-101961 in Juniper Junos can crash BGP daemons via crafted peer packets, threatening connectivity across regulated and public digital services. Patch and audit ECMP policies to maintain DPI resilience. |
| 3 | 2 | CVE-2026-101973 | Foundational Junos OS network backbone software deployed across government, finance, and healthcare infrastructure; DoS risk to PKI-managed edge devices warrants patching in regulated environments. | Juniper Junos OS faces a remote DoS risk in its PKI enrollment service, impacting foundational network backbones across government and regulated sectors. While requiring specific configuration, patching remains critical for maintaining availability in public digital infrastructure. |
| 3 | 2 | CVE-2026-101982 | General Infrastructure: Foundational Juniper Junos routing underpins critical national and enterprise networks, with root RCE risk in BGP/EVPN peering. | Core network routing isn't just about uptime—it's a trust boundary. This TIER 2 Juniper Junos flaw shows how a single BGP/EVPN misconfiguration can grant root access to the backbone of critical infrastructure. Patching and strict peering controls are non-negotiable for DPI resilience. |
| 3 | 2 | CVE-2026-101986 | Foundational networking infrastructure (Juniper Junos) explicitly supports digital public infrastructure as underlying network fabric, impacting government, finance, and healthcare deployments. | Critical unauthenticated bypass in Juniper Junos management interfaces (TIER 2) highlights the persistent risk to foundational network infrastructure. Even when segmented, compromised routers and firewalls can become pivot points across government, finance, and healthcare environments—patching and strict management VLAN controls remain essential. |
| 3 | 2 | CVE-2026-101990 | TIER 2 BGP routing daemon RCE in Juniper Junos OS impacts core network infrastructure, indirectly affecting all DPI sectors reliant on stable routing and transport. | A critical TIER 2 vulnerability in Juniper’s BGP routing daemon could enable remote code execution on core network infrastructure. While exploitation requires a compromised BGP peer, the potential for widespread routing disruption makes immediate patching vital for government, finance, and healthcare networks. |
| 3 | 2 | CVE-2026-102077 | Critical edge router DoS affecting telecom, finance, government, and healthcare backbone infrastructure via IPv6/NAT exhaustion. | Juniper MX routers face a Tier 2 DoS risk that could halt traffic for finance, government, and healthcare networks. Ensure source NAT and IPv6 configs are patched or rate-limited to protect critical edge infrastructure. |
| 3 | 2 | CVE-2026-110385 | General infrastructure RCE in a widely deployed enterprise and government document collaboration platform supporting critical administrative workflows. | Government and enterprise document collaboration platforms face a critical RCE risk in ONLYOFFICE Document Server. With JWT validation often disabled by default, attackers can hijack internal document processing workflows—patch to v10.0 and enforce strict token controls now. |
| 3 | 2 | CVE-2026-110607 | Finance sector relevance due to direct impact on e-commerce payment rails, transaction integrity, and financial accounts. | A leftover developer test endpoint in an open-source e-commerce platform allows authenticated buyers to bypass payment verification, underscoring the financial risks of unsecured transaction endpoints in public-facing digital services. |
| 3 | 2 | CVE-2026-110613 | Finance sector relevance due to exposure of e-commerce transaction data, payment amounts, and customer account details. | Broken access control in open-source e-commerce platforms can expose sensitive financial transaction data. Ensuring strict authorization filters on public-facing APIs is critical for protecting customer payment information and maintaining regulatory compliance. |
| 3 | 2 | CVE-2026-15176 | Foundational general infrastructure (web server/reverse proxy) underpinning public-facing DPI services; requires configuration hardening to prevent DoS/RCE. | A critical NGINX vulnerability underscores the importance of auditing reverse proxy configurations across public-facing digital services. While exploitation requires specific setups, foundational infrastructure demands proactive patching and config reviews to protect citizen and enterprise access layers. |
| 3 | 2 | CVE-2026-33796 | Tier 2 critical RCE in Juniper Junos OS routing daemon impacts foundational network infrastructure supporting regulated and public digital services. | Core routing infrastructure remains a high-value target: a Tier 2 RCE in Juniper Junos OS highlights the need to audit BGP Monitoring Protocol (BMP) configurations across public and enterprise networks. |
| 3 | 2 | CVE-2026-55386 | Authenticated SQLi in a self-hosted invoicing platform risks exfiltration of financial records and payment data, aligning with the Finance sector. | Financial data security remains critical for self-hosted business platforms. This authenticated SQLi in InvoiceShelf highlights the need for strict input validation and MFA to protect sensitive payment and accounting records from targeted exfiltration. |
| 3 | 2 | CVE-2026-82026 | Kubernetes management tool with RCE vulnerability impacts foundational infrastructure for government cloud platforms and regulated enterprise environments. | Internal Kubernetes management tools often fly under the radar, but missing authorization in Skyhook IO Radar can hand attackers full cluster control. As public sector and regulated sectors rely on cloud-native stacks, securing internal APIs is critical for DPI resilience. |
| 3 | 2 | CVE-2026-89068 | Critical unauthenticated LDAP auth bypass in widely deployed enterprise file transfer platform hosting sensitive healthcare/financial data. | Unauthenticated LDAP bypass in Progress MOVEit Transfer (CVSS 9.8) threatens secure B2B and regulated data exchanges. Organizations relying on DMZ-exposed file transfer for healthcare or financial workflows should prioritize patching immediately. |
| 3 | 2 | CVE-2026-89074 | Tier 2 high-severity Unicode encoding flaw in Progress MOVEit Transfer, a general infrastructure MFT platform widely deployed across regulated industries for secure external data exchanges. | Public-facing enterprise file transfer portals face renewed scrutiny as CVE-2026-89074 exposes a high-impact Unicode encoding flaw in Progress MOVEit Transfer. While exploitation requires valid credentials, regulated organizations relying on MFT for secure partner and citizen data exchanges should prioritize patching and enforce strict access controls. |
| 3 | 2 | CVE-2026-94197 | General cloud-native infrastructure (Kubernetes ingress) critical for hosting regulated public, financial, and healthcare services; auth bypass impacts edge security posture. | Kubernetes ingress controllers are the front door for modern cloud-native services. This TIER 2 auth bypass in F5 NGINX NIC shows how misconfigured external auth policies can undermine edge security for regulated workloads. Patch or validate headers to protect citizen and enterprise data. |
| 3 | 2 | CVE-2026-97629 | Foundational reverse proxy flaw bypassing mTLS client certificate verification, directly impacting Digital Identity and Finance sector access controls. | NGINX deployments relying on mTLS for secure access face a session forgery risk that bypasses client certificate checks. While requiring specific caching configs, this Tier 2 flaw underscores the need to harden SSL session handling in public-facing identity and financial services. |
| 2 | 2 | CVE-2026-102068 | Tier 2 remote DoS in Juniper Junos OS Evolved routing infrastructure, explicitly noted for its impact on national network resilience and foundational connectivity. | Foundational routing infrastructure underpins national network resilience. This Tier 2 Juniper Junos OS vulnerability demonstrates how targeted DoS attacks on BGP/LDP authentication can disrupt critical connectivity across public and regulated enterprise environments. |
| 2 | 2 | CVE-2026-66877 | TIER 2 CI/CD authorization bypass in Gitea affects self-hosted development infrastructure explicitly noted for use in government and healthcare digital service pipelines. | Self-hosted CI/CD platforms are critical infrastructure for secure public-sector software development. This TIER 2 vulnerability in Gitea underscores the importance of hardening runner approval gates and concurrency controls to protect government and healthcare code pipelines. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-71433.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100232.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100406.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101338.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101339.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101938.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101957.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101960.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101962.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101966.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101974.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101978.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101981.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101983.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101984.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101987.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101988.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101989.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101992.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101993.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102011.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102015.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102016.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102020.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102022.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102023.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102024.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102025.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102028.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102029.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102031.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102032.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102033.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102041.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102049.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102050.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102051.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102055.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102057.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102060.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102061.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102063.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102066.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102067.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102069.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102071.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102072.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102078.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102079.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102081.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102086.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102175.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102183.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102476.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102986.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103415.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104143.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105106.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105429.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107350.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109439.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110359.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110449.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110609.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110614.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110615.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110616.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110633.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110634.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110668.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110830.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110834.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110836.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110857.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110872.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15102.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50218.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53613.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53614.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53615.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54554.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55387.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71854.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86476.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86562.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86565.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86567.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89069.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94200.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96615.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-101936.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-102018.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-102019.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-102039.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-102040.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-102058.md` — heuristic TIER 3/4
