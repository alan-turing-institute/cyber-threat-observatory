# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-18 12:33:39Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-13`
- **Included count:** 143

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-102210 | Critical unauthenticated RCE in Windows Text Shaping directly threatens government, healthcare, and financial services relying on Windows infrastructure. | A CVSS 9.8, zero-barrier RCE in Windows Text Shaping poses immediate risk to public and regulated services. Patching is mandatory as no network-level mitigations exist for this foundational OS flaw. |
| 5 | 2 | CVE-2026-103849 | Unauthenticated RCE in widely deployed e-commerce platforms directly threatens financial transaction integrity and payment data, aligning with the Finance DPI sector. | Critical unauthenticated RCE in Adobe Commerce/Magento exposes public-facing e-commerce storefronts to immediate compromise. Finance and retail operators must prioritize patching to protect payment processing and customer transaction data. |
| 5 | 1 | CVE-2026-104935 | TIER 1 authentication bypass in Ivanti VPN appliances directly compromises Government, Finance, and Healthcare remote access infrastructure, enabling unauthenticated RCE and credential theft. | Actively exploited TIER 1 flaw in Ivanti Connect Secure bypasses authentication on internet-facing VPNs, granting attackers root access and AD credentials. Critical for Government, Finance, and Healthcare sectors relying on secure remote access—patching is the only mitigation. |
| 5 | 2 | CVE-2026-108131 | Core enterprise identity provider (AD FS) vulnerability enabling unauthenticated identity spoofing, directly impacting Digital Identity infrastructure and federated SSO trust boundaries. | Unauthenticated spoofing in Microsoft AD FS breaks federated identity trust boundaries, posing a direct risk to enterprise and public-sector SSO deployments. Patch promptly and enforce strict network segmentation to protect critical identity infrastructure. |
| 5 | 2 | CVE-2026-109758 | Digital Identity sector: Enterprise authentication gateway with default static SCIM bearer token enables unauthorized identity provisioning and RCE via chaining. | Perforce Helix Authentication Service ships with a static default SCIM token, exposing enterprise identity provisioning to unauthorized access and remote code execution. Patch or rotate tokens immediately to secure your IdP integrations. |
| 5 | 2 | CVE-2026-110116 | Unauthenticated RCE in a core government digital transformation and IdAM platform, directly impacting public-sector identity management and administrative infrastructure. | A critical unauthenticated path traversal in Risesoft-y9's government IdAM platform enables immediate RCE, highlighting the urgent need for strict network segmentation and patching in public-sector digital infrastructure. |
| 5 | 2 | CVE-2026-48382 | Critical RCE in Adobe AEM impacts Government, Finance, and Healthcare sectors relying on the platform for citizen-facing portals and service delivery. | Adobe AEM faces a critical authorization flaw (CVE-2026-48382) enabling remote code execution without user interaction. Public sector and regulated enterprises using AEM for citizen portals must patch immediately to protect digital infrastructure integrity. |
| 5 | 2 | CVE-2026-48383 | Unauthenticated RCE in Adobe Experience Manager, a widely deployed CMS for government citizen portals and financial services, posing direct risk to public-facing digital infrastructure. | Critical unauthenticated RCE in Adobe Experience Manager demands immediate attention for government and financial institutions relying on AEM for citizen-facing portals. Patching and network segmentation are essential to protect public digital services from full system compromise. |
| 5 | 2 | CVE-2026-69783 | Foundational Windows OS privilege escalation impacting Government, Finance, Healthcare, and Identity infrastructure post-compromise. | A TIER 2 Windows Update flaw enables silent local privilege escalation, threatening the foundational OS layer across all DPI sectors. Patching and least-privilege controls are critical to stop ransomware and lateral movement in regulated environments. |
| 5 | 2 | CVE-2026-69802 | Unauthenticated RCE in Microsoft AD CS/NDES compromises enterprise certificate issuance and authentication infrastructure, directly impacting Digital Identity and government/regulated sector access controls. | A new TIER 2 vulnerability in Microsoft’s Active Directory Certificate Services allows unauthenticated remote code execution, threatening the certificate-based authentication backbone of enterprise and government digital infrastructure. Patching and network segmentation are critical to protect identity anchors and prevent lateral movement. |
| 5 | 2 | CVE-2026-70175 | Directly compromises ASP.NET Core Identity's password-reset and account-confirmation workflows, enabling account takeover across public-facing Digital Identity systems. | A high-severity flaw in ASP.NET Core Identity lets attackers hijack password-reset emails, risking mass account takeovers in public-facing and regulated web apps. Patching is critical for any organization relying on .NET for citizen or customer identity management. |
| 5 | 2 | CVE-2026-83511 | Core Digital Identity infrastructure (AD FS) enabling federated SSO for government and enterprise services is vulnerable to unauthenticated network spoofing. | A TIER 2 flaw in Microsoft AD FS exposes internet-facing federated identity providers to unauthenticated spoofing, underscoring the critical need for MFA and immediate patching in public-sector and enterprise SSO deployments. |
| 5 | 2 | CVE-2026-83674 | Core enterprise IdP (AD FS) vulnerability enabling unauthenticated identity spoofing, directly impacting federated SSO and access control for government, healthcare, and financial digital services. | Microsoft AD FS faces a high-severity identity spoofing flaw that could undermine federated SSO trust boundaries. For DPI operators, this underscores the critical need to harden edge-facing IdPs and enforce strict federation protocol validation. |
| 5 | 2 | CVE-2026-83780 | Foundational Windows kernel RCE impacting government, finance, healthcare, and identity infrastructure deployments. | Unauthenticated kernel RCE in Windows CCFFilter poses immediate risk to public-sector and regulated enterprise infrastructure. Prioritize patching for internet-exposed servers and critical service endpoints. |
| 5 | 2 | CVE-2026-83934 | Foundational Windows OS vulnerability (GDI+ RCE) underpinning Government, Finance, Healthcare, and Digital Identity infrastructure globally. | A TIER 2 Windows GDI+ buffer overflow demands attention across all DPI sectors. While user interaction is required, this foundational OS flaw underscores the critical need for rapid patching and email filtering in government, healthcare, and financial networks. |
| 5 | 2 | CVE-2026-85922 | TIER 2 authentication bypass in Azure Key Vault directly impacts Digital Identity and regulated cloud infrastructure by risking exposure of foundational certificates, keys, and secrets. | A new TIER 2 flaw in Azure Key Vault could let attackers bypass authentication controls and steal critical cryptographic secrets. For DPI and regulated cloud environments, this underscores the need for Private Endpoints and strict RBAC to protect identity foundations. |
| 5 | 2 | CVE-2026-85925 | Core cloud cryptographic infrastructure (Azure Key Vault) managing secrets and certificates critical to Digital Identity, Finance, and Government authentication systems. | A TIER 2 privilege escalation in Azure Key Vault could compromise the cryptographic backbone of digital identity and regulated services. Organizations should audit RBAC policies and monitor for anomalous access changes to protect critical secrets and certificates. |
| 5 | 2 | CVE-2026-96222 | Core identity federation flaw in Microsoft AD FS enabling unauthenticated identity spoofing, directly impacting Digital Identity, Government, Healthcare, and Finance sectors. | A TIER 2 flaw in Microsoft AD FS allows unauthenticated attackers to spoof identities by bypassing certificate validation. For any organization relying on federated identity for government, healthcare, or financial services, patching and network segmentation are critical before the next cycle. |
| 4 | 2 | CVE-2026-100218 | Foundational remote access infrastructure for public and private sector workforce connectivity, enabling unauthenticated RCE on internet-facing perimeter servers. | Unauthenticated RCE in Microsoft RD Gateway poses a direct threat to public and enterprise remote access architectures. As a perimeter-facing component critical for workforce connectivity, patching and zero-trust migration are essential to protect government and regulated service delivery. |
| 4 | 2 | CVE-2026-101294 | Enterprise middleware (IBM WebSphere) with OIDC authentication bypass impacts Finance, Government, and Healthcare deployments relying on federated identity. | IBM WebSphere's OIDC token validation flaw (CVE-2026-101294) poses a targeted risk to regulated sectors using federated identity. While requiring explicit configuration, Finance and Government IT teams should verify patch status to prevent authentication bypass in critical middleware. |
| 4 | 2 | CVE-2026-102203 | General infrastructure TIER 2 RCE in Windows Server RPC impacts the foundational OS layer supporting government, finance, and healthcare digital services. | CVE-2026-102203: TIER 2 Windows RPC RCE threatens core DPI infrastructure. While user interaction is required, patching Windows Server is critical to protect regulated sector environments from systemic compromise. |
| 4 | 2 | CVE-2026-102217 | Foundational Windows privilege escalation via WebDAV impacts enterprise and public-sector infrastructure, enabling lateral movement across government, finance, and healthcare networks. | A new Windows WebDAV privilege escalation (CVE-2026-102217) highlights the persistent risk of legacy file-sharing protocols in modern enterprise environments. For DPI operators, patching and disabling unused WebDAV services remains critical to protecting cross-sector digital infrastructure. |
| 4 | 2 | CVE-2026-102225 | Core Windows OS RCE vulnerability impacting enterprise and government IT stacks, requiring patching across regulated digital infrastructure. | A TIER 2 Windows Text Shaping RCE (CVE-2026-102225) highlights the persistent risk of user-triggered exploits in foundational OS layers. DPI operators should prioritize patching and disable auto-preview of untrusted attachments to protect government and enterprise endpoints. |
| 4 | 2 | CVE-2026-102862 | TIER 2 privilege escalation in Microsoft SharePoint Server, a foundational collaboration platform widely deployed across government agencies and public sector digital infrastructure. | Government and public sector IT teams should prioritize patching CVE-2026-102862 in SharePoint Server. This TIER 2 flaw allows authenticated low-privilege users to escalate to admin rights, risking sensitive document stores and internal workflows critical to digital public services. |
| 4 | 2 | CVE-2026-104875 | Digital Identity: Authorization bypass in self-hosted cloud service allows emergency contacts to bypass recovery notice periods and fully take over accounts, impacting identity lifecycle and 2FA controls. | Self-hosted identity and cloud services must harden account recovery flows. This TIER 2 flaw in Ente shows how trusted relationships can be weaponized to bypass 2FA and seize full account control. |
| 4 | 2 | CVE-2026-105895 | Critical authenticated RCE in Adobe AEM 6.5, a foundational CMS explicitly tied to Government, Finance, and Healthcare public-facing digital services. | Adobe AEM 6.5 faces a critical authenticated RCE (CVE-2026-105895) that threatens public-facing digital services. With widespread adoption in government, finance, and healthcare, patching is urgent to protect citizen portals and maintain service integrity. |
| 4 | 2 | CVE-2026-105899 | Critical unauthenticated RCE in Adobe ColdFusion, a foundational enterprise web server explicitly deployed across Finance, Government, and Healthcare sectors. | Unauthenticated RCE (CVSS 10.0) in Adobe ColdFusion demands immediate patching for public sector and regulated enterprises. As a foundational web server hosting legacy finance, government, and healthcare apps, this low-barrier exploit path poses a severe risk to critical digital infrastructure. |
| 4 | 2 | CVE-2026-106624 | Unauthenticated RCE in Adobe ColdFusion, a legacy web server widely deployed in government, finance, and healthcare sectors. | Critical unauthenticated RCE in Adobe ColdFusion (CVE-2026-106624) poses immediate risk to government, finance, and healthcare deployments relying on this legacy enterprise web server. Patching is urgent as no workarounds exist. |
| 4 | 2 | CVE-2026-106626 | Enterprise CMS widely deployed across government, finance, and healthcare for public-facing digital services; RCE risk impacts regulated web infrastructure. | Adobe Experience Manager remains a backbone for government and enterprise digital services, making this TIER 2 RCE a priority for patching cycles. Enforce strict access controls and MFA for admin accounts to mitigate the high-privilege exploitation barrier. |
| 4 | 2 | CVE-2026-106634 | Foundational enterprise CMS widely deployed across Government, Healthcare, and Finance for public-facing service portals, requiring urgent patching for national digital infrastructure resilience. | Adobe Experience Manager (AEM) path traversal (CVE-2026-106634) poses a high-impact risk to public-facing digital services. While authentication is required, the potential for RCE on internet-exposed publish nodes makes immediate patching critical for government, healthcare, and finance portals. |
| 4 | 2 | CVE-2026-61642 | TIER 2 HTTP request smuggling in Squid proxy enables cache poisoning and security bypass, directly threatening the integrity of public-facing identity, finance, and government portals that rely on it as foundational routing infrastructure. | Squid proxy users: a new TIER 2 HTTP request smuggling flaw (CVE-2026-61642) allows attackers to poison caches and bypass upstream security controls. With no workarounds available, patching to v7.6+ is critical for any organization running public-facing or regulated digital services. |
| 4 | 2 | CVE-2026-69898 | Foundational Windows kernel flaw enabling local privilege escalation, explicitly tied to government and public-sector IT estates in the report. | Windows kernel privilege escalation (CVE-2026-69898) highlights the persistent risk to public-sector IT estates. Even without remote triggers, local footholds can cascade into full system compromise—prompt patching remains essential for DPI resilience. |
| 4 | 2 | CVE-2026-70096 | Critical RCE in Windows RichEdit control impacts foundational OS/Office stacks widely deployed across government and national digital infrastructure. | A TIER 2 critical RCE in the Windows Rich Text Edit control underscores the enduring risk to foundational government and enterprise infrastructure. While not internet-facing by default, internal document processing remains a critical attack surface for national digital services. |
| 4 | 2 | CVE-2026-70127 | Foundational DNS infrastructure flaw enabling unauthenticated RCE, directly impacting routing, authentication resolution, and service discovery across all DPI sectors and national digital resilience. | Unauthenticated RCE in Windows DNS Server (CVE-2026-70127) poses a systemic risk to digital public infrastructure. As DNS underpins authentication and service discovery across government, finance, and healthcare, patching and network segmentation are critical to safeguard national digital resilience. |
| 4 | 2 | CVE-2026-70183 | General infrastructure vulnerability in a foundational web framework enabling authenticated privilege escalation, directly impacting public-sector and regulated enterprise deployments. | A race condition in Microsoft’s ASP.NET Core Blazor framework allows authenticated users to bypass authorization controls. Public-sector and enterprise teams should prioritize patching this foundational stack and enforce server-side access validation. |
| 4 | 2 | CVE-2026-70188 | Critical HTTP/2 smuggling flaw in ASP.NET Core/Kestrel, a foundational web runtime underpinning public-facing services across Finance, Healthcare, Government, and Digital Identity sectors. | Public-facing web services built on ASP.NET Core face a critical HTTP/2 smuggling risk that can bypass authentication and WAF controls. With a ready-to-use PoC and no temporary mitigations, DPI operators across finance, health, and government should prioritize patching Kestrel immediately. |
| 4 | 2 | CVE-2026-70213 | RCE in Microsoft Power Apps impacts government and public-sector agencies relying on the platform for citizen-facing services and internal workflows. | Microsoft Power Apps faces a TIER 2 RCE vulnerability that could disrupt citizen-facing government services and enterprise workflows. While exploitation requires user interaction, public sector agencies should prioritize patching and strict origin policies to protect critical digital infrastructure. |
| 4 | 2 | CVE-2026-70242 | Zero-click RCE in Microsoft Outlook impacts enterprise communication infrastructure widely deployed across Government and Finance sectors. | A zero-click, network-accessible RCE in Microsoft Outlook demands immediate attention for public sector and financial institutions. With no user interaction required, this TIER 2 vulnerability underscores the critical need for rapid patching and hardened email security controls across regulated environments. |
| 4 | 2 | CVE-2026-70266 | Foundational enterprise collaboration platform widely deployed across Government, Healthcare, and Finance sectors for intranets and document management, making authenticated SQLi highly material to public digital infrastructure. | Microsoft SharePoint’s prevalence in government and regulated sectors makes this authenticated SQLi a critical watch item for DPI operators. Prompt patching and strict access controls are essential to prevent privilege escalation in public-facing portals and internal collaboration hubs. |
| 4 | 2 | CVE-2026-77206 | General Infrastructure / Government: Foundational IPsec VPN gateway software underpinning secure remote access and site-to-site connectivity for public and regulated networks. | An unauthenticated DoS flaw in Libreswan IPsec VPNs threatens the availability of critical government and enterprise remote access tunnels. Patching or rate-limiting IKE traffic is essential to maintain secure connectivity for public and regulated services. |
| 4 | 2 | CVE-2026-77207 | Unauthenticated remote DoS in Libreswan IPsec VPN gateways disrupts critical remote access and inter-agency connectivity for government and healthcare networks. | Internet-facing IPsec VPNs are the backbone of secure remote access for public sector and healthcare networks. This unauthenticated DoS in Libreswan can drop critical inter-agency tunnels with a single malformed packet—patching is mandatory before sustained outages hit citizen-facing services. |
| 4 | 2 | CVE-2026-77496 | Foundational Windows OS RCE vulnerability impacting Government, Finance, Healthcare, and Identity infrastructure through ubiquitous desktop/server deployments. | A TIER 2 Windows Imaging Component flaw enables remote code execution via crafted images, reminding DPI operators that foundational OS layers remain a critical attack surface across all regulated sectors. Patching and application control are essential to protect citizen-facing and financial services. |
| 4 | 2 | CVE-2026-77910 | Foundational enterprise email infrastructure with a privilege escalation flaw, explicitly impacting Government, Finance, and Healthcare communications and data confidentiality. | Microsoft Exchange Server faces a high-severity privilege escalation flaw (CVE-2026-77910) that threatens core communications across government, finance, and healthcare. While exploitation requires valid credentials, the direct path to administrative control makes immediate patching critical for regulated environments. |
| 4 | 2 | CVE-2026-81839 | Foundational CI/CD platform underpinning secure software supply chains for Government, Finance, Healthcare, and Digital Identity systems. | GitLab's CI/CD privilege escalation flaw highlights the hidden risks in DevOps pipelines that power critical public services. Even with authentication barriers, misconfigured project transfers can expose sensitive government and financial infrastructure—patching and auditing pipeline policies is essential. |
| 4 | 2 | CVE-2026-83519 | Core Windows OS vulnerability underpinning Government, Finance, and Healthcare infrastructure, enabling unauthenticated RCE and lateral movement across enterprise networks. | A critical Windows OS flaw (CVE-2026-83519) grants unauthenticated remote code execution, posing a severe lateral-movement risk across Government, Finance, and Healthcare networks. Patching is mandatory as no workarounds exist. |
| 4 | 2 | CVE-2026-83693 | Critical unauthenticated RCE in Windows OS core service impacts foundational government and enterprise infrastructure, requiring prioritized patching and network segmentation. | A critical, unauthenticated RCE in Windows Error Reporting (CVE-2026-83693) underscores the persistent risk to foundational government and enterprise infrastructure. Even without wild exploitation, securing internal OS services and enforcing strict network segmentation remain vital for DPI resilience. |
| 4 | 2 | CVE-2026-83768 | Windows kernel LPE impacts foundational Government and General Infrastructure, enabling full system compromise across public-sector and regulated environments. | A TIER 2 Windows kernel vulnerability enables local privilege escalation to SYSTEM, posing a critical post-compromise risk to government and enterprise infrastructure. Patching remains essential to protect foundational public services from lateral movement and credential theft. |
| 4 | 2 | CVE-2026-83770 | Critical unauthenticated RCE in Windows Text Shaping underpins government and enterprise IT stacks, requiring immediate patching across regulated public infrastructure. | A critical, zero-barrier RCE in Windows Text Shaping (CVE-2026-83770) threatens the foundational OS layer of government and enterprise networks. With no mitigations beyond patching, DPI operators must prioritize immediate updates to secure public-facing and internal services. |
| 4 | 2 | CVE-2026-83837 | Windows kernel LPE impacts government and public-sector IT infrastructure, requiring prioritized patching to protect digital public services from post-compromise escalation. | Windows remains the backbone of government and public-sector IT. This TIER 2 local privilege escalation highlights why post-compromise defense and rapid patching are critical for protecting digital public infrastructure. |
| 4 | 2 | CVE-2026-83874 | Core Windows OS vulnerability impacting foundational national digital infrastructure and enterprise server/desktop environments across all regulated sectors. | A TIER 2 Windows ETW buffer overflow (CVE-2026-83874) underscores the persistent risk to foundational OS layers in national digital infrastructure. While user interaction is required, patching Windows 10/11 and Server environments remains critical for maintaining resilient public and enterprise services. |
| 4 | 2 | CVE-2026-83910 | Critical unauthenticated RCE in Windows RPC runtime impacts foundational OS infrastructure deployed across government, healthcare, finance, and digital identity environments. | Unauthenticated remote code execution in Windows RPC (CVE-2026-83910) poses a systemic risk to the OS backbone of regulated sectors. Prioritize patching and network segmentation to protect critical public and enterprise infrastructure. |
| 4 | 2 | CVE-2026-83928 | TIER 2 Windows LSASS RCE directly impacts Digital Identity and General Infrastructure, threatening authentication integrity across Government, Finance, and Healthcare deployments. | A TIER 2 Windows LSASS vulnerability (CVE-2026-83928) highlights the critical intersection of OS security and digital identity. While requiring low-privilege access, compromise of this core authentication engine poses systemic risks to regulated sectors relying on Windows-based identity management. |
| 4 | 2 | CVE-2026-85836 | Foundational Windows kernel LPE impacting enterprise servers and workstations that underpin government, finance, and healthcare digital services. | A TIER 2 Windows kernel privilege escalation (CVE-2026-85836) highlights the persistent post-compromise risks in foundational OS infrastructure. While requiring local access, it underscores the critical need for rigorous patching and least-privilege controls across government and regulated enterprise environments. |
| 4 | 2 | CVE-2026-85863 | Windows OS local privilege escalation underpins enterprise and government endpoint/server infrastructure, requiring patching to protect foundational DPI compute layers. | Local privilege escalation in Windows endpoints and servers (CVE-2026-85863) highlights the ongoing need for rigorous patch management and least-privilege controls across government and enterprise infrastructure. Even post-compromise flaws demand attention to protect foundational DPI workloads. |
| 4 | 2 | CVE-2026-85884 | Core Windows 11 OS privilege escalation impacting foundational compute layers across government and public sector IT environments. | A public PoC for a Windows 11 local privilege escalation (CVE-2026-85884) highlights the persistent risk to foundational government and enterprise endpoints. Patching and least-privilege controls remain critical for protecting public digital infrastructure. |
| 4 | 2 | CVE-2026-85926 | High-severity unauthenticated RCE in Windows SSTP VPN stack impacts core remote access infrastructure widely deployed across government, finance, and healthcare environments. | Unauthenticated remote code execution in Windows SSTP VPN gateways poses a critical risk to public-sector and regulated enterprise remote access. Patching and disabling unused RRAS roles are essential to protect foundational government and healthcare infrastructure. |
| 4 | 2 | CVE-2026-87696 | Core enterprise email platform deeply integrated with Active Directory/Azure AD identity systems, widely deployed across government, finance, and healthcare sectors. | Microsoft Exchange Server faces a TIER 2 privilege escalation flaw that could allow authenticated attackers to bypass cryptographic checks and escalate privileges. Given Exchange's deep ties to enterprise identity management and its widespread use in government and regulated sectors, timely patching remains critical for protecting digital public infrastructure. |
| 4 | 2 | CVE-2026-87697 | Foundational .NET runtime deserialization flaw (RCE) impacting backend services across Government, Finance, and Healthcare sectors. | A Tier 2 deserialization vulnerability in Microsoft .NET (CVE-2026-87697) poses a high-impact RCE risk to regulated enterprise backends. While user interaction limits automated exploitation, the framework's ubiquity in government, finance, and healthcare systems makes prompt patching and secure serialization practices critical for DPI resilience. |
| 4 | 2 | CVE-2026-88080 | Foundational Windows OS privilege escalation impacting all regulated sectors (Government, Finance, Healthcare, Identity) deployed on Microsoft infrastructure. | A TIER 2 Windows Installer flaw offers high post-compromise value for attackers targeting regulated environments. Patching and restricting installer execution remain critical for protecting government, healthcare, and financial systems running on Windows. |
| 4 | 2 | CVE-2026-88112 | Foundational Windows DNS Server RCE explicitly tied to availability and integrity risks across government, finance, healthcare, and identity provider ecosystems. | DNS is the silent backbone of digital public infrastructure. This TIER 2 Windows DNS RCE highlights how foundational network services require vigilant patching to protect government, financial, and healthcare name resolution from systemic disruption. |
| 4 | 2 | CVE-2026-88155 | Tier 2 RCE in Microsoft SharePoint Server, a core enterprise collaboration platform widely deployed across government, healthcare, and finance intranets and document management systems. | Microsoft SharePoint Server faces a Tier 2 remote code execution flaw (CVE-2026-88155) that could compromise internal collaboration hubs. While it requires valid credentials, the high impact on government and regulated-sector intranets makes patching and MFA enforcement critical this cycle. |
| 4 | 2 | CVE-2026-88177 | Foundational Windows OS privilege escalation affecting all regulated sectors (Government, Finance, Healthcare, Identity) reliant on Microsoft infrastructure for citizen and enterprise services. | Windows remains the backbone of public and regulated digital services. This TIER 2 local privilege escalation in the Desktop Window Manager demands prompt patching across government, healthcare, and finance environments to prevent post-compromise host takeover. |
| 4 | 2 | CVE-2026-89111 | Critical SSRF in SAP Cloud SDK enables OAuth2 credential theft, directly impacting multi-tenant identity and access management in Finance, Government, and Healthcare deployments. | A critical SSRF in the SAP Cloud SDK for Python could allow attackers to steal OAuth2 credentials from multi-tenant enterprise apps. With SAP BTP widely powering regulated services in finance, government, and healthcare, patching this identity-layer flaw is essential to prevent credential exfiltration and account takeover. |
| 4 | 2 | CVE-2026-89113 | TIER 2 SQL injection in SAP Commerce Cloud directly impacts the Finance sector by threatening payment processing, transaction integrity, and customer account data in enterprise e-commerce deployments. | Enterprise e-commerce platforms are critical financial infrastructure. This TIER 2 SQL injection in SAP Commerce Cloud highlights how authenticated API flaws can compromise payment processing and transaction data, reminding regulated sectors to enforce strict input validation and MFA on commerce APIs. |
| 4 | 2 | CVE-2026-91013 | Tier 2 stored XSS in Adobe Commerce/Magento directly impacts Finance sector e-commerce infrastructure, risking payment token theft and merchant account takeover. | E-commerce platforms handling consumer payments face a critical stored XSS risk (CVE-2026-91013) in Adobe Commerce/Magento. While requiring user interaction, the potential for session hijacking and payment data exposure makes patching essential for Finance-sector digital storefronts. |
| 4 | 2 | CVE-2026-92909 | Unauthenticated RCE in Adobe Commerce/Magento directly threatens internet-facing financial transaction and payment processing systems, aligning with the Finance DPI sector. | Critical unauthenticated RCE in Adobe Commerce/Magento exposes internet-facing B2B storefronts to immediate server compromise. Finance and retail operators relying on this stack for payment processing should prioritize patching to protect transaction data and merchant revenue systems. |
| 4 | 2 | CVE-2026-92910 | Unauthenticated authorization bypass in Adobe Commerce/Magento B2B portals threatens financial transaction integrity and payment/billing data flows, directly impacting the Finance DPI sector. | Enterprise e-commerce platforms like Adobe Commerce and Magento are critical nodes in the financial supply chain. This unauthenticated authorization bypass (CVE-2026-92910) exposes B2B portals to data theft and transaction manipulation, underscoring the need for rapid patching in regulated commerce environments. |
| 4 | 2 | CVE-2026-92911 | TIER 2 stored XSS in Adobe Commerce/Magento directly impacts the Finance sector by threatening payment processing integrity and customer account security in public-facing e-commerce infrastructure. | Public-facing e-commerce platforms handling financial transactions face a new TIER 2 stored XSS risk (CVE-2026-92911) in Adobe Commerce and Magento. While exploitation requires low-privilege access and user interaction, the potential for session takeover and transaction interception makes immediate patching essential for regulated digital storefronts. |
| 4 | 2 | CVE-2026-94453 | Foundational IPsec VPN infrastructure widely deployed in Government and Finance sectors for secure remote access and inter-agency connectivity. | Libreswan VPN gateways underpin secure remote access for government and financial institutions worldwide. While IKE-over-TCP is disabled by default, administrators should verify configurations and patch to prevent remote DoS on critical public infrastructure. |
| 4 | 2 | CVE-2026-96113 | Foundational DNS infrastructure vulnerability impacting enterprise and public sector networks, enabling unauthenticated RCE and lateral movement across all DPI sectors. | Unauthenticated RCE in Windows DNS Server (CVE-2026-96113) poses a critical lateral movement risk for enterprise and public sector networks. Patching and strict network segmentation are essential to protect foundational identity and service resolution layers. |
| 4 | 2 | CVE-2026-96219 | Foundational Windows OS/LSASS flaw enabling unauthenticated RCE and credential theft, directly impacting government, finance, and healthcare server deployments. | A critical, unauthenticated RCE in Windows LSASS (CVE-2026-96219) grants SYSTEM-level access and credential dumping across enterprise environments. While no wild exploits are confirmed yet, its foundational impact on national digital infrastructure makes immediate patching and network segmentation essential for regulated sectors. |
| 4 | 2 | CVE-2026-96230 | Foundational web framework (ASP.NET Core) underpinning public-facing services across government, finance, healthcare, and digital identity sectors. | A TIER 2 XSS flaw in Microsoft ASP.NET Core highlights the persistent risk to foundational web stacks powering regulated public services. Patching and strict CSP enforcement remain critical for protecting citizen and financial data. |
| 4 | 2 | CVE-2026-96249 | Tier 2 local privilege escalation in Windows 11/Server 2025 kernel, explicitly noted as foundational infrastructure underpinning all DPI sectors. | Windows Server 2025 and Windows 11 face a Tier 2 kernel use-after-free flaw enabling local privilege escalation. While requiring initial access, this vulnerability poses a critical post-compromise risk to the foundational OS layer supporting government, finance, and healthcare DPI deployments. Patching and least-privilege controls are essential. |
| 4 | 2 | CVE-2026-96916 | Foundational Windows NTFS flaw enables local privilege escalation across enterprise and public-sector servers, posing systemic post-compromise risk to Digital Identity, Healthcare, Finance, and Government infrastructure. | A TIER 2 Windows NTFS buffer overflow highlights the hidden risks in core OS components: while requiring local access, it serves as a critical post-compromise escalation vector for ransomware and credential theft across government, healthcare, and financial server estates. Prioritize patching high-value endpoints to block lateral movement. |
| 4 | 2 | CVE-2026-96951 | Foundational Windows OS vulnerability affecting enterprise and government endpoints, listed on CISA KEV with confirmed in-wild exploitation. | A CISA-listed Windows Shell flaw is actively exploited in phishing campaigns, bypassing MOTW protections on endpoints widely used across government and critical infrastructure. Patching and endpoint controls remain essential for national digital resilience. |
| 4 | 2 | CVE-2026-97749 | Critical zero-interaction RCE in Microsoft Outlook impacts foundational enterprise email infrastructure deployed across Government, Finance, Healthcare, and Identity sectors, threatening operational continuity for digital public services. | A zero-interaction RCE in Microsoft Outlook could silently compromise endpoints across government, healthcare, and financial institutions. With no user click required, patching this TIER 2 vulnerability is critical to protect the email infrastructure underpinning digital public services. |
| 4 | 2 | CVE-2026-97805 | Unauthenticated network RCE in a foundational Windows kernel driver directly impacts Government and General Infrastructure sectors, requiring urgent patching across public-sector IT environments. | A critical, unauthenticated RCE in the Windows Partition Management Driver (CVE-2026-97805) poses immediate risk to government and enterprise networks. With no authentication required and kernel-level impact, public-sector IT teams should prioritize patching and network segmentation ahead of the standard cycle. |
| 4 | 2 | CVE-2026-97814 | Critical unauthenticated RCE in Windows Text Shaping impacts foundational OS infrastructure underpinning Government, Finance, Healthcare, and Digital Identity deployments. | A critical, zero-interaction RCE in Windows threatens the foundational OS layer supporting public services and regulated sectors. Immediate patching is essential to protect Government, Finance, and Healthcare infrastructure from unauthenticated network attacks. |
| 3 | 2 | CVE-2025-57739 | Widely deployed enterprise email gateway supporting Government, Finance, and Healthcare communications; requires patching to prevent targeted RCE and lateral movement in regulated environments. | FortiMail’s authenticated SQLi vulnerability (CVE-2025-57739) underscores the need for strict credential hygiene and network segmentation in regulated sectors. While not publicly exploited, targeted attacks on government and financial email gateways could lead to full system compromise—patch promptly. |
| 3 | 2 | CVE-2026-100219 | Critical unauthenticated RCE in Windows QUIC stack underpins foundational infrastructure for government, finance, and healthcare deployments. | A TIER 2, CVSS 9.8 flaw in Microsoft’s QUIC transport layer exposes unauthenticated remote code execution across Windows Server and 11. While not sector-specific, this foundational networking vulnerability demands immediate patching for any regulated or public-facing infrastructure relying on modern HTTP/3 traffic. |
| 3 | 2 | CVE-2026-100220 | TIER 2 Windows OS media decoder RCE impacts foundational government and enterprise infrastructure, requiring prioritized patching for internet-exposed endpoints. | A TIER 2 Windows media decoder flaw (CVE-2026-100220) enables RCE via crafted video files, highlighting the need for rapid patching across government and enterprise endpoints. While user interaction is required, the broad OS footprint makes it a priority for public-sector IT teams. |
| 3 | 2 | CVE-2026-103030 | Foundational HTTP client library for Dart/Flutter leaks authentication headers on cross-origin redirects, risking credential theft in regulated mobile/web applications. | A widely used Flutter/Dart HTTP client silently leaks auth tokens and cookies on cross-origin redirects. Developers building regulated or citizen-facing apps should patch immediately to prevent credential theft. |
| 3 | 2 | CVE-2026-105445 | Foundational CI/CD and container registry infrastructure widely deployed across public and private sectors, posing broad software supply chain integrity risks. | A TIER 2 flaw in Docker Hub’s account conversion workflow allowed silent PAT hijacking, threatening CI/CD pipelines and container registries across public and private sectors. Organizations relying on cloud-native deployments should audit token scopes and enforce organization-level access controls to safeguard their software supply chains. |
| 3 | 2 | CVE-2026-106173 | Enterprise SIEM infrastructure critical for government and regulated sector security monitoring; unauthenticated RCE risks compromising national security log aggregation and incident response. | A critical unauthenticated RCE in Fortinet FortiSIEM highlights the hidden risks in internal security monitoring stacks. While not internet-facing by default, compromised SIEMs can blind government and enterprise defenders—reinforcing the need for strict network segmentation and rapid patching of core security infrastructure. |
| 3 | 2 | CVE-2026-106612 | General infrastructure app server widely deployed across government, healthcare, and finance sectors; authorization bypass to RCE poses systemic risk to public-facing enterprise workloads. | Adobe ColdFusion remains a critical backbone for many government and enterprise portals. This TIER 2 authorization flaw enables remote code execution for low-privilege users, highlighting the urgent need to patch legacy app servers hosting public digital services. |
| 3 | 2 | CVE-2026-106621 | Critical unauthenticated RCE in Adobe ColdFusion, a widely deployed enterprise application server that underpins regulated finance, government, and healthcare web services. | Unauthenticated remote code execution in Adobe ColdFusion poses a direct threat to internet-facing enterprise applications. Organizations in regulated sectors should prioritize patching APSB26-144 and hardening reverse proxy controls to protect critical backend infrastructure. |
| 3 | 2 | CVE-2026-106622 | Tier 2 unauthenticated SSRF in Adobe ColdFusion, a foundational enterprise web server widely deployed across regulated finance, government, and healthcare environments. | Critical unauthenticated SSRF in Adobe ColdFusion (CVE-2026-106622) enables privilege escalation on public-facing instances. Regulated sectors relying on ColdFusion for citizen or financial services should prioritize patching and outbound traffic restrictions. |
| 3 | 2 | CVE-2026-110083 | General infrastructure CMS widely deployed by public sector and financial institutions for citizen-facing web services. | Adobe AEM SQLi (CVE-2026-110083) requires low-priv auth but poses data breach risks for public sector and financial web portals. Patching and strict access controls are critical for regulated CMS deployments. |
| 3 | 2 | CVE-2026-110084 | Enterprise CMS widely deployed in government and public services; authenticated XPath injection enables privilege escalation and data extraction. | Adobe AEM 6.5 faces a TIER 2 XPath injection flaw enabling authenticated users to bypass security controls. Public sector and enterprise CMS deployments should apply hotfix GRANITE-75052 to protect sensitive repository data. |
| 3 | 2 | CVE-2026-12655 | Unauthenticated admin takeover in Rockwell OT I/O modules deployed across regulated energy, water, and critical infrastructure networks (General Infrastructure). | Critical infrastructure operators should prioritize patching Rockwell ArmorBlock I/O firmware to 3.013, as an unauthenticated webserver bypass allows full device control on internal OT networks. Network segmentation remains essential for defense-in-depth. |
| 3 | 2 | CVE-2026-34633 | Tier 2 SSRF in Adobe ColdFusion enables privilege escalation and internal pivoting, impacting Finance, Government, and Healthcare deployments that rely on this enterprise web server. | Enterprise web servers like Adobe ColdFusion remain critical infrastructure for regulated sectors. This authenticated SSRF (CVE-2026-34633) highlights the need for strict egress filtering and least-privilege access in Finance, Government, and Healthcare environments. |
| 3 | 2 | CVE-2026-55823 | TIER 2 SQLi in the Frappe framework, a general infrastructure stack explicitly deployed across Finance, Government, and Healthcare ERP/CRM systems. | A high-severity SQL injection in the Frappe framework highlights the hidden risks in low-code platforms powering regulated ERP and citizen services. Even with authentication barriers, unpatched report endpoints in Finance and Government deployments remain a critical attack vector for data exfiltration. |
| 3 | 2 | CVE-2026-69639 | Critical RCE in Windows Libarchive impacts foundational government and enterprise server/desktop infrastructure, requiring urgent patching across public-sector IT environments. | A CVSS 9.8 remote code execution flaw in Windows Libarchive threatens foundational government and enterprise infrastructure. With no user interaction required, public-sector IT teams must prioritize patching Windows 10/11 and Server deployments immediately. |
| 3 | 2 | CVE-2026-69883 | Critical unauthenticated RCE in Windows iSCSI impacts enterprise and government storage infrastructure, requiring strict network segmentation. | CVE-2026-69883 enables unauthenticated kernel RCE via Windows iSCSI, posing a severe lateral movement risk for internal storage networks in government and enterprise environments. Enforce strict TCP 3260 segmentation and prioritize patching. |
| 3 | 2 | CVE-2026-69913 | TIER 2 RCE in Windows TCP/IP stack affects foundational server infrastructure widely deployed across government, finance, and healthcare environments. | A TIER 2 remote code execution flaw in the Windows TCP/IP stack highlights ongoing risks to foundational public and enterprise infrastructure. Timely patching of Windows Server deployments remains essential for protecting regulated digital services. |
| 3 | 2 | CVE-2026-69976 | Broad Windows endpoint vulnerability impacting general enterprise and public infrastructure, requiring patching across regulated environments. | Microsoft's Remote Desktop Client RCE (CVE-2026-69976) underscores the persistent risk in widely deployed OS components. Though user interaction is required, its broad footprint across enterprise and public infrastructure endpoints makes timely patching essential for DPI resilience. |
| 3 | 2 | CVE-2026-69997 | Foundational Windows RDP client vulnerability impacting enterprise and public infrastructure remote access, requiring patching across regulated environments. | Windows RDP client RCE (CVE-2026-69997) highlights the persistent risk in foundational remote access tools. While user interaction is required, public sector and regulated enterprises must prioritize patching to secure critical infrastructure endpoints. |
| 3 | 2 | CVE-2026-70059 | General infrastructure: core Windows OS privilege escalation impacting server and endpoint deployments across government, finance, and healthcare backends. | A TIER 2 Windows OLE vulnerability enables local privilege escalation across widely deployed server and endpoint environments. Though requiring initial access, it remains a critical post-compromise vector for attackers targeting national digital infrastructure and regulated enterprise backends. |
| 3 | 2 | CVE-2026-70153 | Critical Windows OS vulnerability affecting foundational infrastructure across all DPI sectors via unauthenticated RCE in the Print Spooler. | Windows environments underpin nearly all digital public infrastructure. This TIER 2, CVSS 9.8 Print Spooler RCE demands immediate patching and network segmentation to protect foundational government, healthcare, and financial systems from lateral movement and full host takeover. |
| 3 | 2 | CVE-2026-70157 | Critical unauthenticated RCE in Windows Server/Desktop impacts foundational infrastructure supporting all regulated and public digital services. | A TIER 2 critical RCE in Windows Server and desktops demands immediate patching for any organization running regulated or public-facing digital services. Network segmentation and service hardening are essential while updates roll out. |
| 3 | 2 | CVE-2026-70181 | Foundational web framework for public-sector and regulated enterprise APIs; DoS risk to citizen-facing services via multipart upload endpoints. | ASP.NET Core DoS vulnerability highlights the need for strict request throttling in public-facing government and enterprise APIs. Patching and WAF rules are critical to protect citizen services from resource exhaustion attacks. |
| 3 | 2 | CVE-2026-70186 | General infrastructure framework explicitly tied to government and public sector deployments, posing DoS risk to citizen-facing web services. | ASP.NET Core underpins many government and enterprise web services. This TIER 2 DoS flaw underscores the need to audit non-default configurations like HTTP/3 and maintain strict patching cycles for public-facing infrastructure. |
| 3 | 2 | CVE-2026-70197 | Foundational .NET runtime RCE impacts public-facing APIs and enterprise services across regulated sectors. | A Tier 2 RCE in Microsoft .NET's networking stack highlights the hidden risks in foundational frameworks. Even with a niche coding trigger, public-facing APIs and enterprise services must patch immediately to prevent unauthenticated remote code execution. |
| 3 | 2 | CVE-2026-70291 | Foundational enterprise email client used across government, finance, and healthcare; zero-interaction RCE poses broad endpoint compromise risk to regulated sectors. | Microsoft Outlook’s zero-interaction RCE (CVE-2026-70291) highlights the persistent risk to regulated sectors relying on ubiquitous enterprise endpoints. Patching and email filtering remain critical for protecting government, finance, and healthcare networks. |
| 3 | 2 | CVE-2026-70571 | Core enterprise email infrastructure widely deployed across regulated and public sectors, requiring prompt patching despite high exploit complexity. | Unauthenticated RCE in Microsoft Exchange Server (CVE-2026-70571) underscores the enduring risk to public-facing email gateways. While exploitation barriers remain high, regulated organizations should prioritize cumulative updates and network segmentation to safeguard critical collaboration infrastructure. |
| 3 | 2 | CVE-2026-83578 | Foundational Windows OS component underpinning public infrastructure and enterprise automation, requiring strict patching and network segmentation. | A critical RCE in Windows PowerShell (CVE-2026-83578) underscores the importance of internal network segmentation for public infrastructure. While not internet-facing by default, this vulnerability enables high-impact lateral movement, making timely patching essential for regulated environments. |
| 3 | 2 | CVE-2026-83643 | General Infrastructure / Government: Foundational Windows OS flaw enabling RCE on core enterprise and public-sector systems. | CVE-2026-83643 underscores the critical need to patch foundational OS components like Windows Error Reporting, which underpin government and enterprise digital infrastructure. While exploitation requires user interaction, the network-reachable RCE risk demands immediate attention across regulated environments. |
| 3 | 2 | CVE-2026-83738 | Foundational Windows OS kernel vulnerability impacting enterprise and public infrastructure deployments across regulated sectors. | A TIER 2 local privilege escalation in the Windows AFD driver underscores the critical need to harden foundational OS layers that underpin government, finance, and healthcare digital services. Timely patching remains essential for post-compromise resilience. |
| 3 | 2 | CVE-2026-83748 | Critical unauthenticated RCE in core Windows OS infrastructure underpinning government, finance, and healthcare enterprise deployments. | A CVSS 9.8 Windows RCE highlights the need for rapid patching and strict network segmentation across public-sector and regulated enterprise environments. Protecting foundational OS layers remains critical for DPI resilience. |
| 3 | 2 | CVE-2026-83797 | Foundational Windows OS/server vulnerability impacting enterprise and public-sector infrastructure across all regulated sectors. | Kernel RCE in Windows Partition Management Driver (CVE-2026-83797) demands immediate patching for government and enterprise environments. While user interaction is required, the SYSTEM-level impact makes it a critical foundational risk for digital public infrastructure. |
| 3 | 2 | CVE-2026-84012 | General infrastructure vulnerability enabling unauthenticated RCE on internet-facing remote access gateways critical to regulated and public-sector operations. | CVE-2026-84012 allows unauthenticated remote code execution on Microsoft RD Gateway, a foundational component for secure remote access in enterprise and government environments. Immediate patching and strict network segmentation are essential to protect public-facing digital infrastructure. |
| 3 | 2 | CVE-2026-85341 | Core Windows OS kernel vulnerability underpinning digital public infrastructure across all sectors; local privilege escalation poses high post-compromise risk to enterprise and government endpoints. | Foundational OS vulnerabilities like this TIER 2 Windows kernel flaw remind us that local privilege escalation remains a critical threat to digital public infrastructure. Patching Windows servers and endpoints is essential to prevent attackers from pivoting to SYSTEM-level access after an initial breach. |
| 3 | 2 | CVE-2026-85792 | TIER 2 unauthenticated RCE in Windows RRAS, a core server networking role underpinning VPN and remote access across regulated enterprise and public-sector environments. | Foundational Windows server roles like RRAS remain critical attack surfaces for DPI infrastructure. CVE-2026-85792 underscores the need for strict service hardening and patching in regulated environments, even when exploitation requires explicit configuration. |
| 3 | 2 | CVE-2026-85809 | Critical unauthenticated RCE in Windows RRAS, a foundational enterprise networking/VPN role that underpins connectivity for regulated and public-sector digital services. | A CVSS 9.8 remote code execution flaw in Windows RRAS highlights the persistent risk to enterprise networking infrastructure. While not default-enabled, internet-facing VPN gateways and routing nodes in regulated environments require immediate patching and strict firewall controls. |
| 3 | 2 | CVE-2026-85928 | Critical unauthenticated RCE in Windows Server/Desktop kernel driver impacts foundational enterprise infrastructure supporting regulated and public digital services. | A TIER 2 Windows kernel RCE (CVE-2026-85928) enables unauthenticated remote code execution across Windows 10/11 and Server deployments. While not internet-facing by default, it poses a severe lateral movement risk for DPI and regulated enterprise environments—prioritize patching and network segmentation. |
| 3 | 2 | CVE-2026-85933 | Foundational Windows OS vulnerability enabling local privilege escalation to SYSTEM, directly impacting enterprise and government IT environments that rely on standard Windows deployments. | A new Windows Print Spooler flaw (CVE-2026-85933) provides a straightforward path to SYSTEM-level access, highlighting why foundational OS patching and service hardening remain critical for government and enterprise infrastructure. |
| 3 | 2 | CVE-2026-85936 | Foundational Windows OS vulnerability impacting enterprise desktops and servers across all DPI sectors, requiring patching to prevent RCE. | A high-severity Windows Shell flaw (CVE-2026-85936) enables network-based RCE but requires user interaction. While it underpins all DPI sectors equally, timely patching remains critical for enterprise and government endpoints. |
| 3 | 2 | CVE-2026-88120 | Foundational internal networking infrastructure (Windows DHCP) with unauthenticated RCE, impacting enterprise and public sector network segmentation and lateral movement defenses. | Unauthenticated RCE in Windows DHCP Server (CVE-2026-88120) underscores the critical risk to internal network infrastructure. Even without internet exposure, compromised DHCP services can enable SYSTEM-level lateral movement across enterprise and public sector environments. |
| 3 | 2 | CVE-2026-88163 | General infrastructure RCE in Microsoft SharePoint, widely deployed across public sector, finance, and healthcare for citizen portals and sensitive document management. | Authenticated RCE in Microsoft SharePoint (CVE-2026-88163) poses a Tier 2 risk to public sector and regulated enterprise portals. While requiring valid credentials, its broad footprint in government and healthcare document management makes patching a priority for internet-exposed deployments. |
| 3 | 2 | CVE-2026-88166 | Core enterprise collaboration platform widely deployed across government, finance, and healthcare sectors for critical document management and internal operations. | A Tier 2 authenticated RCE in Microsoft SharePoint highlights the persistent risk to widely deployed enterprise collaboration stacks. For government and regulated sectors, this reinforces the need for strict IAM controls, network segmentation, and rapid patching to protect critical internal infrastructure. |
| 3 | 2 | CVE-2026-88178 | Critical RCE in Microsoft Office PowerPoint, a foundational enterprise and government productivity suite enabling initial access across public sector and regulated environments. | A critical TIER 2 RCE in Microsoft Office PowerPoint highlights how foundational enterprise productivity tools remain a primary attack surface for government and regulated sectors. Organizations should prioritize patching, enforce strict email filtering, and monitor for anomalous Office-to-shell execution chains. |
| 3 | 2 | CVE-2026-88219 | Foundational Windows RPC RCE impacting government and enterprise infrastructure, requiring coordinated patching across critical IT environments. | A high-severity Windows RPC runtime flaw (CVE-2026-88219) exposes government and enterprise networks to remote code execution. While user interaction is required, the broad footprint across critical infrastructure makes immediate patching essential for DPI operators. |
| 3 | 2 | CVE-2026-90532 | Unauthenticated RCE in Adobe Experience Manager, a widely deployed enterprise CMS powering public-facing digital services across government, finance, and healthcare sectors. | Critical unauthenticated RCE in Adobe Experience Manager (CVE-2026-90532) exposes internet-facing publish instances to immediate compromise. Organizations in regulated sectors should prioritize patching and network segmentation to protect citizen and customer-facing digital services. |
| 3 | 2 | CVE-2026-96232 | Foundational .NET runtime flaw enabling unauthenticated memory disclosure across public-sector and enterprise web services. | Unauthenticated out-of-bounds read in Microsoft .NET runtime (CVE-2026-96232) exposes sensitive memory across widely deployed public-facing services. Patching is critical for DPI environments relying on .NET for citizen-facing and enterprise applications. |
| 3 | 2 | CVE-2026-96236 | General infrastructure framework widely deployed in government and enterprise web services; trivial unauthenticated DoS threatens critical public-facing availability. | ASP.NET Core powers countless public-facing government and enterprise web services. This trivial, unauthenticated DoS flaw can crash servers with simple scripts—patch your .NET runtimes immediately to keep critical digital infrastructure online. |
| 3 | 2 | CVE-2026-96307 | TIER 2 local privilege escalation in Windows Installer impacts Windows Server/10/11, serving as foundational infrastructure for government and enterprise DPI deployments. | A TIER 2 local privilege escalation in Windows Installer (CVE-2026-96307) poses a significant post-compromise risk to government and enterprise IT. Prompt patching is critical to secure foundational DPI infrastructure against lateral movement and ransomware deployment. |
| 3 | 2 | CVE-2026-96308 | Core Windows Server/OS privilege escalation affecting foundational General Infrastructure across regulated sectors. | TIER 2 Windows Installer LPE (CVE-2026-96308) poses a post-compromise risk to enterprise and public-sector Windows Server deployments. Patching remains critical to block lateral movement and ransomware campaigns targeting core infrastructure. |
| 3 | 2 | CVE-2026-96856 | Core Windows OS privilege escalation affecting government and enterprise server/desktop infrastructure, critical for post-compromise defense in public sector environments. | A TIER 2 Windows WMI buffer overflow enables local privilege escalation across enterprise and government IT stacks. While requiring initial access, it remains a critical post-compromise vector for ransomware and APTs targeting public infrastructure—patching and least-privilege controls are essential. |
| 3 | 2 | CVE-2026-96924 | Foundational Windows OS/server vulnerability with unauthenticated RCE, directly impacting government and enterprise IT infrastructure reliant on Microsoft stacks. | Critical unauthenticated RCE in Windows OLE (CVE-2026-96924) demands immediate patching for government and enterprise networks. With no workarounds and a 9.8 CVSS, this foundational OS flaw highlights the urgency of proactive patch management in regulated digital infrastructure. |
| 3 | 2 | CVE-2026-96931 | Core Windows NTFS driver LPE impacts foundational server and endpoint infrastructure across regulated government, finance, and healthcare deployments. | A Tier 2 local privilege escalation in the Windows NTFS driver highlights the critical need for rapid patching and strict least-privilege controls across government and enterprise server fleets. |
| 3 | 2 | CVE-2026-96952 | Foundational Windows OS component affecting government, finance, and healthcare server/desktop deployments; requires coordinated patching across regulated environments. | Windows Media Foundation RCE (CVE-2026-96952) lands at Tier 2, underscoring the need for regulated sectors to prioritize patching and strict media file filtering across Windows fleets. |
| 3 | 2 | CVE-2026-96957 | General infrastructure: foundational .NET runtime flaw requiring patching across enterprise and public-sector applications that depend on the framework. | A high-severity cryptographic signature bypass in Microsoft .NET SDK demands immediate patching for any organization running enterprise or citizen-facing applications on the framework. While user interaction is required, the foundational nature of .NET makes this a critical platform dependency for DPI environments. |
| 3 | 2 | CVE-2026-97016 | Critical RCE in foundational enterprise email client explicitly deployed across government, finance, and healthcare sectors. | A zero-interaction RCE flaw in Microsoft Outlook highlights the persistent risk to foundational enterprise infrastructure. Even without confirmed wild exploitation, its ubiquitous deployment across regulated sectors demands immediate patching and enhanced email filtering. |
| 2 | 2 | CVE-2026-63146 | General infrastructure collaboration platform with unauthenticated RCE poses direct risk to regulated and public-sector deployments relying on it for secure remote work. | CVE-2026-63146 delivers unauthenticated RCE in Agora Project via installer flaws. Regulated and public-sector teams should patch to 26.10.0 immediately to protect collaboration endpoints from network-based compromise. |
| 2 | 2 | CVE-2026-70013 | Tier 2 kernel RCE in Windows iSCSI driver impacts server infrastructure widely deployed across government and regulated public services. | Internal storage networks in public sector and enterprise environments face a new Tier 2 Windows kernel RCE risk. Prioritize patching and iSCSI segmentation to safeguard critical infrastructure. |
| 2 | 2 | CVE-2026-75732 | TIER 2 RCE in Adobe AEM impacts foundational enterprise CMS infrastructure widely deployed in regulated/public-facing digital services. | A critical authorization flaw in Adobe Experience Manager (CVE-2026-75732) enables RCE for authenticated users. While lacking sector-specific tags, this TIER 2 vulnerability underscores the need for strict access controls and patching in public-facing enterprise CMS deployments across regulated environments. |
| 2 | 2 | CVE-2026-83851 | Foundational Windows OS kernel flaw impacting enterprise and public infrastructure fleets, requiring coordinated patching across regulated environments. | A TIER 2 Windows Partition Management Driver vulnerability (CVE-2026-83851) highlights the ongoing need for rigorous patch management in DPI ecosystems. While user interaction is required, unpatched Windows Server and desktop deployments in public or regulated sectors remain vulnerable to privilege escalation—schedule October 2026 updates and enforce network segmentation. |
| 2 | 2 | CVE-2026-84008 | General infrastructure DoS in the .NET runtime threatens availability of enterprise and government-hosted web services. | A public PoC for a .NET Framework DoS vulnerability highlights the fragility of foundational enterprise runtimes. Even without in-wild exploitation, government and regulated services relying on .NET must patch promptly to avoid availability breaches. |
| 2 | 2 | CVE-2026-85814 | General infrastructure vulnerability in Windows OS impacting enterprise and government IT environments, requiring network segmentation and patching. | Critical Windows Media Foundation flaw (CVE-2026-85814) enables unauthenticated RCE across Windows 10/11 and Server. While currently unexploited, government and enterprise IT must prioritize patching and network segmentation to mitigate lateral movement risks. |
| 2 | 2 | CVE-2026-85823 | Tier 2 local privilege escalation in Windows OS, foundational infrastructure supporting cross-sector digital public services. | A new Tier 2 local privilege escalation in Windows (CVE-2026-85823) highlights the persistent value of baseline OS hardening. Though requiring local access, timely patching remains essential for securing the foundational layers of government and enterprise digital infrastructure. |
| 2 | 2 | CVE-2026-88092 | Tier 2 HTTP request smuggling in ASP.NET Core, a general infrastructure framework explicitly noted for use in public-sector and enterprise environments. | Critical HTTP request smuggling in Microsoft ASP.NET Core (Kestrel) threatens public-facing APIs and web services, including government deployments; patches are available for .NET 8, 9, and 10. |
| 2 | 2 | CVE-2026-88117 | TIER 2 RCE in Windows DHCP Server impacts foundational internal networking infrastructure critical to government, finance, and healthcare enterprise environments. | Internal network hygiene matters: a TIER 2 use-after-free in Windows DHCP Server could grant SYSTEM-level access to core enterprise infrastructure. While confined to internal networks, it underscores the need for strict segmentation and patching in regulated digital services. |
| 2 | 2 | CVE-2026-88173 | TIER 2 unauthenticated RCE in Windows BITS impacts core server infrastructure that underpins regulated and public-sector digital services. | A high-complexity race condition in Windows BITS enables unauthenticated remote code execution across enterprise server fleets. While exploitation barriers are significant, the systemic impact on foundational OS services warrants immediate patching for regulated infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-46773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-58771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-58772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-58773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-58774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100200.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100201.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100212.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100214.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100217.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100222.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100225.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101020.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102073.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102189.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102191.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102193.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102194.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102196.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102201.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102214.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102215.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102218.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102226.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102227.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102231.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102232.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102233.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102234.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102857.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103316.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103499.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103553.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103554.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103555.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103558.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103565.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103568.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103569.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103928.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105010.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105013.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105443.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105591.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105592.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105593.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105595.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105596.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105597.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105598.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105599.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105732.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105733.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106042.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106613.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106614.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106615.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106617.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106618.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106620.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108132.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108135.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108377.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108396.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108398.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108400.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108461.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108465.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108468.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109403.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109677.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109938.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110109.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110112.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110115.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110215.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110217.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12656.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13138.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18228.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-23705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-23707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53420.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53562.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54641.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55562.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58280.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59241.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63162.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63350.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65147.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65148.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65173.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65674.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67625.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68836.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69227.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69387.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69471.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69596.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69633.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69733.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69736.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69743.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69884.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69923.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69926.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69931.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69957.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69966.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69984.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69987.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69988.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69991.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69992.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69998.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70006.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70010.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70012.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70015.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70021.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70023.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70027.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70033.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70038.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70049.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70051.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70060.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70062.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70066.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70067.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70069.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70086.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70102.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70103.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70106.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70112.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70115.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70123.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70131.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70132.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70138.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70139.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70140.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70143.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70144.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70156.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70167.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70190.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70205.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70212.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70215.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70218.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70222.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70225.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70228.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70229.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70230.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70233.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70241.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70251.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70257.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70258.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70282.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70343.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70566.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70580.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72968.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73027.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74031.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74033.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74040.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74041.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76001.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77100.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83499.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83510.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83514.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83516.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83518.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83564.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83566.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83567.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83568.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83569.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83570.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83580.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83586.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83588.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83634.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83635.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83638.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83641.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83642.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83644.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83654.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83666.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83670.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83679.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83690.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83698.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83699.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83700.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83702.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83726.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83732.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83735.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83746.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83769.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83784.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83792.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83796.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83828.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83830.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83834.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83836.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83838.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83841.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83852.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83857.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83859.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83872.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83889.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83899.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83913.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83919.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83921.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83931.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84013.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84016.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84018.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84019.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84020.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85327.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85329.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85338.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85339.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85342.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85343.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85358.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85359.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85362.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85363.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85364.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85365.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85366.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85367.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85368.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85369.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85373.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85377.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85796.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85820.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85828.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85834.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85854.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85855.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85856.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85872.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85919.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85931.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85990.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86063.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87699.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87700.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87702.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88070.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88072.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88073.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88074.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88079.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88081.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88100.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88103.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88106.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88109.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88115.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88116.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88128.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88135.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88139.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88144.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88145.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88147.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88168.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88171.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88180.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88181.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88182.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88186.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88188.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88189.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88191.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88193.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88194.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88196.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88200.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88204.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88206.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90530.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92922.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94512.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94603.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96071.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96186.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96188.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96215.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96217.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96225.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96231.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96233.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96248.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96251.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96312.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96323.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96852.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96913.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96919.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96923.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96928.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96960.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96997.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97001.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97010.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97011.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97012.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97742.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97745.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97746.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97747.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97755.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97769.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97792.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97794.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97809.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97812.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97830.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-102074.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-70031.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-70079.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-70155.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-83655.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-83665.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-83677.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-83855.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-96861.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-96866.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-96945.md` — heuristic TIER 3/4
