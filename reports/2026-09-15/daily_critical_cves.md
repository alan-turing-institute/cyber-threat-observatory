# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-21 13:55:50Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-15`
- **Included count:** 68

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-11926 | Digital Identity: Unauthenticated DoS in IBM Verify Identity Access, a core IdAM gateway critical for national authentication infrastructure. | IBM's Verify Identity Access faces an unauthenticated DoS risk that can halt authentication flows for public-facing services. With no vendor mitigations available, DPI operators must prioritize patching or deploy upstream rate limiting to protect national identity gateways. |
| 5 | 2 | CVE-2026-11929 | Core IAM reverse proxy cryptographic flaw impacting authentication boundaries and session integrity in public-facing Digital Identity deployments. | IBM's Security Verify Identity Access reverse proxy faces a cryptographic validation weakness (CVE-2026-11929) that could undermine authentication integrity. TIER 2 alert for Digital Identity teams: patch IAM gateways and audit edge configurations to protect public-facing access boundaries. |
| 5 | 2 | CVE-2026-41573 | Core IAM/IdP platform (OpenAM) vulnerable to authenticated LDAP injection, risking identity data exfiltration and SSO ecosystem compromise in the Digital Identity sector. | Identity providers are the backbone of digital public infrastructure. This TIER 2 LDAP injection in OpenAM highlights why strict token lifecycle management and API filtering are non-negotiable for protecting citizen and enterprise identity fabrics. |
| 5 | 2 | CVE-2026-44203 | Impacts OpenAM's OAuth 2.0/OIDC authorization flows, enabling session hijacking and token theft in core Digital Identity infrastructure. | A TIER 2 reflected XSS in OpenAM's OAuth/OIDC endpoints highlights the persistent risks in public-facing identity providers. Patching to v16.1.1 is critical to protect token issuance and prevent session hijacking in regulated IdAM deployments. |
| 5 | 2 | CVE-2026-45048 | Core Digital Identity impact: session hijacking in OpenAM IdP allows low-privilege users to steal admin credentials, threatening enterprise and public-sector SSO infrastructure. | OpenAM session hijacking flaw (CVE-2026-45048) lets authenticated users steal admin credentials, highlighting the critical need to patch IdAM platforms and restrict session endpoints in digital identity deployments. |
| 5 | 2 | CVE-2026-45051 | Critical RCE in OpenAM's WebAuthn module threatens core Digital Identity sector infrastructure, risking session hijacking and credential theft across SAML/OIDC federated services. | A critical deserialization flaw in OpenAM’s WebAuthn module could compromise entire identity ecosystems, but exploitation hinges on a specific configuration barrier. For DPI operators, patching to 16.1.1 and hardening attribute write permissions are immediate priorities to protect federated access. |
| 5 | 2 | CVE-2026-45052 | Critical unauthenticated authorization bypass in OpenAM IdP/SSO gateway enables manipulation of core identity federation routing and LDAP profiles, directly impacting the Digital Identity sector. | A critical flaw in OpenAM allows unauthenticated attackers to rewrite identity federation routing and LDAP profiles by default. For any organization relying on SSO or public-facing IdPs, patching or blocking the legacy Liberty SOAP endpoint is now urgent to protect your authentication trust anchor. |
| 5 | 2 | CVE-2026-45794 | Digital Identity: Critical deserialization flaw in OpenAM IdAM platform enables RCE, threatening authentication infrastructure and session management. | Identity infrastructure under threat: A new TIER 2 vulnerability in OpenAM (CVE-2026-45794) allows remote code execution via push notification callbacks. Organizations relying on OpenAM for digital identity must patch immediately to prevent full IdP compromise. |
| 5 | 2 | CVE-2026-46498 | Core Digital Identity sector impact: authorization bypass in OpenAM IdP enables OAuth2/OIDC token forgery, compromising enterprise and public-sector identity infrastructure. | A TIER 2 flaw in OpenAM allows attackers to forge OAuth2/OIDC tokens via a type confusion in the Core Token Store. While it requires a niche Push Notification config, the public PoC and high impact on identity providers make patching critical for DPI stakeholders. |
| 5 | 2 | CVE-2026-46619 | Critical LDAP injection in OpenAM's MSISDN module enables unauthenticated session hijacking, directly impacting Digital Identity and enterprise access management infrastructure. | OpenAM deployments face a critical session takeover risk via an unpatched LDAP injection flaw. Organizations relying on this IdAM gateway should verify MSISDN module configurations and patch immediately to protect digital identity ecosystems. |
| 5 | 2 | CVE-2026-46623 | Core IdAM vulnerability enabling trivial unauthenticated account takeover via OAuth2, directly impacting digital identity infrastructure across government, finance, and healthcare deployments. | A critical flaw in OpenAM’s OAuth2 module silently resets user passwords to their usernames, enabling trivial account takeover. For any organization relying on public-facing identity providers, this TIER 2 vulnerability demands immediate patching to protect federated access and credential integrity. |
| 5 | 2 | CVE-2026-47424 | Core Digital Identity platform (OpenAM) with authenticated RCE impacting OAuth2/OIDC/SAML trust chains and national IdAM infrastructure. | Authenticated RCE in OpenAM's Groovy sandbox threatens core digital identity infrastructure. While requiring admin privileges, compromise of this IdAM gateway breaks federated trust chains and SSO ecosystems—patch or restrict script-edit permissions immediately. |
| 5 | 2 | CVE-2026-47426 | Digital Identity sector: Core IdAM platform flaw enabling OAuth2 client impersonation and cross-realm token minting, directly impacting authentication trust boundaries. | OpenAM's OAuth2 client authentication flaw allows attackers to impersonate registered clients and mint tokens across realms. A critical reminder to audit dynamic registration and JWKS usage in enterprise identity fabrics. |
| 5 | 2 | CVE-2026-53660 | Core IdAM platform (OpenAM) session cookie misconfiguration enables SSO hijacking and forced OAuth/OIDC consent grants, directly impacting Digital Identity infrastructure. | OpenAM's default SSO cookie configuration lacks critical security flags, allowing chained XSS attacks to steal sessions and force OAuth consent approvals. A critical reminder for IdAM admins to enforce HttpOnly/SameSite defaults and monitor consent endpoints. |
| 5 | 2 | CVE-2026-55149 | TIER 2 unauthenticated DoS in Vouch Proxy, a core SSO/OAuth/OIDC authentication gateway, directly impacting Digital Identity infrastructure and session management. | A single HTTP request can crash Vouch Proxy, a widely used SSO/OAuth gateway, causing immediate denial of service for identity management flows. Patch to v0.48.0 is critical for protecting public-facing authentication endpoints. |
| 5 | 2 | CVE-2026-55864 | Unauthenticated SSRF in GeoNetwork, a backbone component for national spatial data infrastructures and government geoportals (~89% government-affiliated deployments). | National mapping agencies and environmental ministries should prioritize patching GeoNetwork immediately. This unauthenticated SSRF offers a ready-to-use pivot into internal government networks, threatening critical spatial data infrastructure. |
| 5 | 2 | CVE-2026-62263 | Critical pre-auth RCE in OpenAM's WebAuthn module directly compromises core Digital Identity infrastructure, enabling credential theft and token manipulation across SSO deployments. | A critical pre-authentication RCE in OpenAM’s WebAuthn module exposes a major IdAM stack to unauthenticated code execution. For digital public infrastructure, this underscores the urgent need to patch identity gateways and harden deserialization filters before credential theft becomes widespread. |
| 5 | 2 | CVE-2026-62379 | Critical unauthenticated RCE in OpenAM, a foundational IAM/IdP platform, directly compromises the Digital Identity sector's authentication and session management layer. | Unauthenticated RCE in OpenAM (CVE-2026-62379) exposes a critical flaw in default IAM deployments, allowing attackers to bypass authentication and seize control of identity infrastructure. Organizations relying on OpenAM for digital identity services must patch immediately or restrict the /authservice endpoint. |
| 5 | 2 | CVE-2026-71047 | Directly impacts enterprise Digital Identity infrastructure by enabling authenticated privilege escalation in Oracle Identity Manager, risking full control over user provisioning and access rights. | A new TIER 2 vulnerability in Oracle Identity Manager (CVE-2026-71047) allows authenticated low-privilege users to achieve full system takeover, threatening the integrity of enterprise digital identity fabrics. Organizations relying on OIM for access management should prioritize the September CSPU patch and enforce strict network segmentation. |
| 5 | 2 | CVE-2026-71133 | Critical unauthenticated takeover in Oracle Access Manager, a foundational IdAM gateway widely deployed for government portals and national digital identity services. | A CVSS 10.0 flaw in Oracle Access Manager lets attackers bypass authentication entirely and seize control of enterprise identity gateways. For DPI operators, this underscores the urgent need to patch edge IdAM systems and enforce strict network segmentation before mass exploitation hits public-sector portals. |
| 5 | 2 | CVE-2026-71163 | Core enterprise IdAM gateway vulnerability impacting authentication, authorization, and session management for public-facing digital services. | Oracle Access Manager's critical auth engine flaw (CVE-2026-71163) lets low-privilege users corrupt identity data and disrupt SSO flows. Patching this Tier 2 vulnerability is essential for protecting public-facing digital identity gateways. |
| 5 | 2 | CVE-2026-73941 | Unauthenticated data exposure in Oracle Access Manager directly compromises core digital identity and authentication infrastructure used across regulated sectors. | A zero-barrier, unauthenticated flaw in Oracle Access Manager could expose session tokens and credentials across public-facing identity gateways. For DPI operators, this underscores the critical need to patch IdAM edge components before attackers turn data exposure into full account takeover. |
| 5 | 2 | CVE-2026-73944 | Critical unauthenticated remote flaw in Oracle Access Manager enables manipulation of IdAM records, directly threatening Digital Identity infrastructure across government, finance, and healthcare. | Unauthenticated remote access to Oracle Access Manager could let attackers rewrite identity records at scale. For DPI operators, immediate patching is critical to protect citizen and enterprise authentication gateways. |
| 5 | 2 | CVE-2026-73947 | Critical unauthenticated remote takeover in Oracle Access Manager, a core enterprise Identity and Access Management (IdAM) gateway handling SSO and MFA. | A critical, unauthenticated flaw in Oracle Access Manager could allow attackers to fully compromise perimeter-facing identity gateways, bypassing MFA and SSO controls. Organizations relying on OAM for digital identity services should prioritize patching immediately. |
| 5 | 2 | CVE-2026-73950 | Critical unauthenticated flaw in Oracle Access Manager allows full takeover of internet-facing identity gateways, directly compromising digital identity trust boundaries for enterprise and public-sector deployments. | A critical, unauthenticated vulnerability in Oracle Access Manager (CVE-2026-73950) enables full takeover of internet-facing identity gateways. Organizations relying on OAM for authentication must patch immediately to safeguard digital identity services and downstream access controls. |
| 5 | 2 | CVE-2026-73958 | Core IAM gateway flaw impacting authentication engines and session management, directly relevant to national digital identity infrastructure and government portals. | Unauthenticated remote takeover of Oracle Access Manager poses a critical risk to digital identity gateways. Organizations relying on OAM for citizen or enterprise authentication must prioritize patching to protect foundational access control mechanisms. |
| 5 | 2 | CVE-2026-83001 | Digital Identity: Core enterprise IdAM gateway vulnerability impacting authentication and session management across regulated sectors. | Oracle Access Manager faces a critical TIER 2 flaw enabling full system takeover for privileged attackers, underscoring the need for strict least-privilege and rapid patching in enterprise identity stacks. |
| 5 | 2 | CVE-2026-83042 | Unauthenticated remote takeover of Oracle Identity Manager (OIM) compromises core IdAM functions, directly impacting Digital Identity infrastructure and credential security. | Critical unauthenticated flaw in Oracle Identity Manager (CVE-2026-83042) allows full system takeover, threatening enterprise identity frameworks and credential stores. Patching and network segmentation are essential for DPI resilience. |
| 5 | 2 | CVE-2026-83059 | Critical unauthenticated LDAP flaw in Oracle Internet Directory compromises foundational enterprise identity infrastructure, directly impacting the Digital Identity sector. | A CVSS 10.0 vulnerability in Oracle Internet Directory allows unauthenticated attackers to fully compromise enterprise LDAP directories. For DPI and regulated environments, this highlights the critical importance of patching core identity infrastructure and enforcing strict network segmentation. |
| 5 | 2 | CVE-2026-83062 | Core enterprise LDAP/IdAM service with unauthenticated RCE, directly impacting digital identity infrastructure across government, finance, and healthcare sectors. | Unauthenticated RCE in Oracle Internet Directory (CVE-2026-83062) threatens the backbone of enterprise digital identity. With a CVSS of 9.8, this LDAP flaw enables full server takeover and rapid lateral movement, making immediate patching critical for regulated sectors relying on centralized authentication. |
| 5 | 2 | CVE-2026-91998 | Critical authorization bypass in Casdoor IAM/SSO platform enables cross-tenant user administration and credential theft, directly impacting Digital Identity infrastructure. | A critical flaw in the open-source IAM platform Casdoor allows attackers with valid OAuth client secrets to bypass authorization and take over user accounts across all tenants. Organizations relying on Casdoor for public-sector or enterprise SSO must patch immediately to protect their digital identity infrastructure. |
| 4 | 2 | CVE-2023-54398 | Critical unauthenticated RCE in widely deployed enterprise ERP software, directly impacting Finance and Government sectors for budgeting, procurement, and transaction processing. | Unauthenticated RCE in Yonyou U8 Cloud ERP is actively exploited in the wild. With confirmed wild exploitation and critical impact on financial and government operations, organizations must prioritize patching and network segmentation immediately. |
| 4 | 2 | CVE-2024-58385 | Actively exploited unauthenticated SQLi in Yonyou U8 CRM, a core ERP/CRM platform widely deployed in finance and government sectors for transaction processing and civic services. | Active exploitation of a critical SQL injection in Yonyou U8 CRM underscores the risks to enterprise ERP systems. With widespread adoption in finance and government sectors, immediate patching and disabling xp_cmdshell are essential to prevent data breaches and potential remote code execution. |
| 4 | 2 | CVE-2026-19780 | TIER 2 authenticated RCE in Koha library system, directly impacting the Government sector via public libraries and municipal archives handling citizen data. | Public libraries and municipal archives running Koha face a TIER 2 authenticated RCE risk that could expose citizen data and disrupt civic information services. Patching and credential hygiene are critical for government-facing deployments. |
| 4 | 2 | CVE-2026-55178 | Authorization bypass in a self-hosted geospatial catalog exposes sensitive land registry and civic planning data, directly impacting government spatial data infrastructures (SDIs) and utility operations. | Geospatial data catalogs are becoming critical nodes in national digital infrastructure, but flawed authorization can turn internal maps into open data dumps. CVE-2026-55178 highlights how trivial API bypasses in tools like GeoLens can expose sensitive land registries and civic planning layers, urging government and utility teams to patch or restrict network access immediately. |
| 4 | 2 | CVE-2026-68950 | Hard-coded root credentials in widely deployed surveillance DVR/NVR systems directly impact Government and Healthcare physical security infrastructure, enabling unauthenticated remote access and data exfiltration. | Public sector and healthcare facilities relying on Digital Watchdog VMAX surveillance systems face a critical risk: hard-coded root credentials allow trivial unauthenticated FTP access. Immediate firmware updates and strict network segmentation are essential to protect sensitive physical security infrastructure. |
| 4 | 2 | CVE-2026-83037 | Critical unauthenticated bypass in Oracle WebCenter Sites threatens government citizen portals and public sector digital service platforms. | Unauthenticated remote takeover in Oracle WebCenter Sites (CVE-2026-83037) poses a direct risk to government citizen portals and public sector digital services. Agencies relying on this CMS for official communications should prioritize patching and network segmentation immediately. |
| 4 | 2 | CVE-2026-83167 | Unauthenticated remote data access in Oracle E-Business Suite, a core ERP platform widely deployed across Finance, Government, and Healthcare sectors for critical business operations. | Oracle E-Business Suite faces a high-impact, unauthenticated data access flaw (CVE-2026-83167) that could expose sensitive financial, government, and healthcare records. Organizations relying on this ERP should prioritize patching and network segmentation to prevent post-compromise data exfiltration. |
| 4 | 2 | CVE-2026-83197 | Critical unauthenticated flaw in Oracle Siebel Financial Accounts exposes sensitive financial records and disrupts banking/insurance operations, directly impacting regulated finance infrastructure. | Financial institutions running Oracle Siebel should prioritize patching CVE-2026-83197: an unauthenticated, CVSS 9.1 flaw that could expose critical account data and halt financial services operations. Network segmentation and WAF rules are essential interim controls while awaiting the September CSPU. |
| 4 | 2 | CVE-2026-83234 | Unauthenticated remote access to Oracle Commerce search infrastructure impacts finance and e-commerce operations handling transactions and customer account data. | Internal commerce admin tools are often overlooked in network segmentation strategies. This unauthenticated flaw in Oracle Commerce underscores the need to secure backend search infrastructure that supports financial transactions and customer data. |
| 4 | 2 | CVE-2026-83243 | TIER 2 access control flaw in Oracle Commerce exposes customer financial data and transaction histories, directly impacting the Finance DPI sector. | Enterprise e-commerce platforms handling payments and customer financial data face a new TIER 2 risk: CVE-2026-83243 allows authenticated attackers to bypass access controls and exfiltrate sensitive transaction data. Finance and regulated commerce operators should prioritize patching and credential hygiene. |
| 4 | 2 | CVE-2026-87129 | Unauthenticated bypass in Oracle Hyperion DRM allows direct manipulation of core financial master data, directly impacting enterprise finance and government treasury operations. | A critical unauthenticated flaw in Oracle Hyperion DRM lets attackers silently alter financial master data like cost centers and account hierarchies. Finance and public-sector teams should prioritize patching and internal network segmentation to protect fiscal reporting and compliance workflows. |
| 4 | 2 | CVE-2026-87171 | Unauthenticated remote exploitation of Oracle Hyperion Financial Management enables unauthorized access and manipulation of critical financial data, directly impacting enterprise finance operations. | Oracle Hyperion Financial Management faces a high-severity, unauthenticated flaw (CVE-2026-87171) that allows attackers to manipulate critical financial data. While typically internal, finance teams must prioritize patching and network segmentation to protect budgeting and reporting systems. |
| 4 | 2 | CVE-2026-87173 | Critical unauthenticated authentication bypass in Oracle Hyperion Financial Management directly impacts the Finance sector by compromising budgeting, consolidation, and regulatory reporting data. | Unauthenticated access to core financial planning systems poses severe compliance and data integrity risks for regulated enterprises. Patching Oracle Hyperion Financial Management is critical to safeguarding internal financial operations and meeting audit requirements. |
| 4 | 2 | CVE-2026-87175 | Critical unauthenticated authentication bypass in Oracle Hyperion Financial Management directly threatens regulated Finance sector operations, budgeting, and reporting infrastructure. | A critical unauthenticated bypass in Oracle Hyperion HFM allows full compromise of financial data without credentials. Finance and government teams managing core budgeting and reporting infrastructure should prioritize patching and strict network segmentation. |
| 4 | 2 | CVE-2026-87176 | Critical unauthenticated authentication bypass in Oracle Hyperion Financial Management directly impacts enterprise financial planning, reporting, and regulatory compliance, with potential government deployment relevance. | CVE-2026-87176 introduces a critical unauthenticated authentication bypass in Oracle Hyperion Financial Management, risking unauthorized access to sensitive financial planning and reporting data. Though typically deployed behind corporate firewalls, this TIER 2 flaw highlights the importance of network segmentation and prompt patching for regulated finance and government operations. |
| 4 | 2 | CVE-2026-87184 | Core financial planning and reporting platform (Finance sector) with unauthenticated RCE, impacting corporate treasuries and public-sector finance operations. | Unauthenticated RCE in Oracle Hyperion Financial Management (CVE-2026-87184) poses a critical risk to enterprise and public-sector finance systems. While typically internal, the CVSS 9.8 flaw underscores the need for strict network segmentation and prompt patching in regulated financial environments. |
| 4 | 2 | CVE-2026-87196 | TIER 2 unauthenticated flaw in Oracle Hyperion Financial Management enables unauthorized read/write access to critical financial data, directly impacting regulated finance and enterprise budgeting operations. | Enterprise financial backends are prime targets for lateral movement. This unauthenticated flaw in Oracle Hyperion Financial Management allows attackers to manipulate critical budgeting and reporting data once inside the network, underscoring the need for strict internal segmentation and prompt patching in regulated finance environments. |
| 4 | 2 | CVE-2026-87200 | Finance sector: Unauthenticated data manipulation in Oracle Hyperion Financial Management threatens corporate accounting integrity and regulatory compliance. | CVE-2026-87200 exposes Oracle Hyperion Financial Management to unauthenticated data tampering, posing a severe risk to financial reporting integrity. Even in internal deployments, this TIER 2 flaw offers attackers a high-value lateral movement primitive to corrupt critical fiscal data. |
| 4 | 2 | CVE-2026-87205 | Directly impacts the Finance sector by enabling unauthenticated extraction of critical budgeting, forecasting, and reporting data from enterprise EPM systems. | Unauthenticated access to Oracle Hyperion Financial Management could expose sensitive corporate and public-sector financial data to internal network threats. Finance and regulated enterprise teams should prioritize patching and enforce strict internal segmentation to protect critical economic operations. |
| 4 | 2 | CVE-2026-87217 | Critical unauthenticated bypass in Oracle Hyperion Financial Management enables unauthorized access and manipulation of enterprise financial planning data, directly impacting the Finance DPI sector. | Enterprise financial planning systems face a critical authentication bypass (CVSS 9.1) that allows unauthenticated internal access to modify budgets and forecasts. Finance and regulated sectors should prioritize patching Oracle Hyperion and verify network segmentation to protect financial data integrity. |
| 4 | 2 | CVE-2026-87223 | Critical unauthenticated flaw in Oracle Hyperion Financial Management enables data manipulation and DoS in core Finance DPI systems. | Financial institutions and regulated enterprises relying on Oracle Hyperion for budgeting and reporting must patch immediately. This unauthenticated vulnerability allows attackers with internal network access to manipulate critical financial data or crash systems, posing severe compliance and operational risks. |
| 4 | 2 | CVE-2026-87230 | CVSS 10.0 vulnerability in Oracle Hyperion Financial Management impacts financial consolidation and reporting in regulated enterprise environments. | CVSS 10.0 flaw in Oracle Hyperion Financial Management threatens financial data integrity and reporting. Critical for regulated finance sectors relying on enterprise performance management. |
| 4 | 2 | CVE-2026-89308 | Unauthenticated RCE in workforce management software widely deployed in Italian public administration, flagged by national cybersecurity agency (ACN). | Critical unauthenticated RCE in TrxTimeATTENDANCE poses a direct risk to government and enterprise HR systems. With an ACN advisory issued, public sector deployments must patch immediately or restrict the exposed ping.php endpoint to prevent full system compromise. |
| 4 | 2 | CVE-2026-91947 | Core remote desktop infrastructure explicitly deployed across government, healthcare, and finance sectors for secure remote access and VDI, making it critical for regulated digital service continuity. | FreeRDP servers underpin remote access for government, healthcare, and finance VDI deployments. This TIER 2 race condition requires authentication but underscores the need to harden RDP gateways and disable unused channels to protect critical remote workforce infrastructure. |
| 3 | 2 | CVE-2026-76688 | Foundational SD-WAN orchestration infrastructure supporting regulated sectors (finance, healthcare, government) with unauthenticated admin bypass risk. | SD-WAN orchestrators form the backbone of modern enterprise networks; an unauthenticated bypass here risks pivoting across branch offices, underscoring the need for strict network segmentation and ZTNA in regulated environments. |
| 3 | 2 | CVE-2026-76690 | Foundational SD-WAN networking infrastructure explicitly deployed across government and critical sectors, where authenticated RCE could compromise branch perimeter security and WAN connectivity. | HPE EdgeConnect SD-WAN gateways face an authenticated RCE vulnerability (CVE-2026-76690) that grants root access. While credential hygiene and MFA are critical barriers, government and enterprise networks must prioritize patching these internet-facing edge devices to protect critical WAN infrastructure. |
| 3 | 2 | CVE-2026-83043 | Enterprise portal middleware widely deployed in government, finance, and healthcare intranets/extranets; full takeover risks disruption to citizen-facing and regulated internal services. | Oracle WebCenter Portal faces a critical unauthenticated takeover flaw (CVSS 9.6) that could disrupt enterprise intranets and extranets across government, finance, and healthcare. While internal by default, patching is urgent for any regulated organization relying on portal-based citizen or partner services. |
| 3 | 2 | CVE-2026-87128 | Critical unauthenticated flaw in Oracle Hyperion DRM, an enterprise master data management platform vital for financial reporting and ERP integrations. | CVE-2026-87128 exposes Oracle Hyperion DRM to unauthenticated data compromise, threatening financial master data and ERP integrity. Organizations must patch immediately and enforce strict internal network segmentation to protect critical reporting workflows. |
| 3 | 2 | CVE-2026-91948 | General infrastructure RDP stack widely deployed in public-sector and enterprise remote access environments, requiring patching to secure foundational connectivity services. | Remote desktop infrastructure remains a critical attack surface for public and enterprise networks. CVE-2026-91948 highlights how build configurations and authentication barriers can mitigate RCE risks in FreeRDP deployments—patching and secure compilation practices are essential for DPI resilience. |
| 3 | 2 | CVE-2026-91949 | Foundational remote desktop infrastructure (FreeRDP) with a pre-auth protocol bypass impacting government, healthcare, and finance deployments that rely on secure remote access. | FreeRDP’s pre-auth protocol bypass (CVE-2026-91949) forces unintended transport states on NLA-only servers, posing a cross-sector risk to government, healthcare, and finance remote access infrastructure. Patch to 3.31.0 or enforce network segmentation to mitigate. |
| 2 | 2 | CVE-2026-55331 | TIER 2 RCE in Android IMS/telephony stack affects a ubiquitous mobile OS explicitly noted as underpinning healthcare, finance, and government deployments. | A TIER 2 remote code execution flaw in Android's core telephony stack highlights the ongoing patching imperative for mobile devices supporting regulated public and enterprise services. |
| 2 | 2 | CVE-2026-81236 | TIER 2 unauthenticated RCE in enterprise thin-client management software; relevant to Government and Healthcare IT infrastructure where WMS is commonly deployed for secure endpoint control. | Unauthenticated RCE in Dell Wyse Management Suite highlights the risks of internal enterprise management stacks. While typically behind firewalls, compromised thin-client controllers can enable lateral movement across regulated Government and Healthcare networks—patching and network segmentation remain critical. |
| 2 | 2 | CVE-2026-81238 | TIER 2 unauthenticated access to enterprise thin-client management suite deployed across healthcare, finance, and government networks. | Dell Wyse Management Suite faces a TIER 2 missing authentication flaw, allowing unauthenticated control over thin-client fleets. Critical for IT admins in regulated sectors to patch and enforce network segmentation. |
| 2 | 2 | CVE-2026-83020 | TIER 2 unauthenticated RCE in Oracle OPSS middleware, broadly impacting government, finance, and healthcare enterprise stacks. | Oracle OPSS unauthenticated RCE (CVE-2026-83020) poses a high lateral-movement risk across enterprise middleware. While typically internal, its CVSS 10.0 score and broad deployment in regulated sectors demand immediate CSPU patching and strict network segmentation. |
| 2 | 2 | CVE-2026-83095 | Tier 2 critical unauthenticated RCE in Oracle Forms middleware, widely deployed in regulated enterprise and government intranets for internal application delivery. | Zero-auth remote takeover in Oracle Forms (CVSS 9.8) threatens regulated intranets and backend databases. Patch immediately and enforce strict network segmentation to block lateral movement. |
| 2 | 2 | CVE-2026-83215 | TIER 2 unauthenticated access flaw in Oracle Siebel CRM, widely deployed across regulated Finance, Healthcare, and Government environments handling sensitive PII. | CVE-2026-83215 allows unauthenticated HTTP access to Oracle Siebel CRM, risking exposure of sensitive customer data. Though classified as general infrastructure, its prevalence in regulated sectors demands immediate patching for enterprise and public-sector deployments. |
| 2 | 2 | CVE-2026-83304 | General enterprise analytics infrastructure frequently deployed in regulated Government, Finance, and Healthcare environments for internal reporting, posing data integrity risks if internal segmentation fails. | Unauthenticated remote flaws in internal enterprise analytics platforms like Oracle OBIEE highlight the hidden risks of 'internal-only' assumptions in regulated sectors. Even without internet exposure, compromised BI servers can expose sensitive government, financial, or healthcare reporting data. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-11728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12351.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12358.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12666.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12667.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16140.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-1758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18115.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19407.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19515.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21586.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21588.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46495.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53966.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55225.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61549.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61667.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61668.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63443.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65831.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66887.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68070.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70913.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73437.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73446.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73926.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73957.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76670.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76677.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76679.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76681.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76683.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76686.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76820.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81240.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83012.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83024.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83041.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83050.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83053.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83055.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83065.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83067.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83069.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83070.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83071.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83073.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83080.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83085.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83106.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83112.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83116.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83125.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83129.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83131.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83132.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83135.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83144.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83148.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83155.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83171.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83180.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83186.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83188.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83189.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83190.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83193.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83194.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83196.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83206.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83212.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83213.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83214.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83217.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83221.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83225.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83226.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83227.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83229.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83230.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83231.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83233.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83240.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83248.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83257.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83263.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83264.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83265.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83282.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83283.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83289.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83291.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83296.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83308.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83311.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83312.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83316.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83323.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83329.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83331.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83338.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83341.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83342.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83344.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83345.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83348.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83350.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83351.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83368.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83420.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83423.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83429.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83434.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83435.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83436.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83437.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83438.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83439.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83440.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83444.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83446.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83447.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83449.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83457.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83465.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83477.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83479.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83481.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83482.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83483.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83487.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85234.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87125.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87131.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87132.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87135.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87137.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87138.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87139.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87140.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87143.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87144.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87147.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87155.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87162.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87167.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87180.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87181.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87182.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87183.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87186.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87188.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87189.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87190.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87193.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87194.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87201.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87206.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87213.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87218.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87221.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87222.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87225.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87226.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87227.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87229.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87231.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87232.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87234.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87240.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87241.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87257.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87258.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87259.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87261.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87264.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87265.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87277.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87289.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88616.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88619.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89025.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89040.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90852.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91925.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91936.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91940.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91968.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91988.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91989.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91992.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92006.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92011.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92053.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92055.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92073.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-19655.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-83222.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-83228.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-87148.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-92062.md` — heuristic TIER 3/4
