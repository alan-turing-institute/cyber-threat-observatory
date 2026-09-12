# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-12 11:16:28Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-08`
- **Included count:** 76

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-53938 | Digital Identity: Pre-authentication heap overflow in the core cjose JWT/JWE library threatens national digital identity platforms, OAuth/OIDC providers, and government credential systems. | A pre-authentication heap overflow in the widely used cjose JWT library could crash or compromise public-facing identity endpoints. National ID platforms and OAuth providers should patch immediately or disable AES-KW JWE decryption for untrusted inputs. |
| 5 | 2 | CVE-2026-53939 | Critical cryptographic flaw in the cjose library breaks JWE confidentiality/integrity, directly impacting OpenID Connect and OAuth 2.0 identity providers and relying parties in the Digital Identity sector. | A zero-key flaw in a foundational JWT/JWE library could silently break encryption for OpenID Connect deployments. Identity teams should audit cjose versions and rotate secrets if using AES-CBC-HMAC algorithms. |
| 5 | 2 | CVE-2026-69546 | Unauthenticated RCE in Microsoft AD DS directly compromises foundational Digital Identity infrastructure for enterprises and government. | A TIER 2 unauthenticated RCE in Microsoft Active Directory highlights the critical need to harden internal identity infrastructure. Even without public exposure, AD DS remains the backbone of government and enterprise digital identity—making segmentation and rapid patching essential. |
| 5 | 2 | CVE-2026-78623 | SQL injection in Okta Access Gateway's SAML processing directly impacts Digital Identity infrastructure and enterprise authentication gateways. | A TIER 2 SQLi in Okta Access Gateway highlights how niche SAML configurations can still expose core identity gateways. Patching and auditing advanced datastore settings are critical for protecting national and enterprise IdAM stacks. |
| 5 | 2 | CVE-2026-78626 | Directly impacts Okta Access Gateway authorization enforcement, a foundational Digital Identity component for secure remote access and SSO in regulated/public sectors. | Okta Access Gateway faces a high-severity authorization bypass that could undermine protected access rules for remote workers and citizen services. Organizations relying on Okta for identity infrastructure should prioritize patching to maintain strict access controls. |
| 5 | 2 | CVE-2026-79576 | Critical SSO authentication bypass in a widely deployed government/enterprise IdAM platform, enabling trivial admin takeover. | A trivial SSO bypass in a major government/enterprise identity platform allows attackers to forge admin sessions without passwords. With a public PoC and predictable user IDs, this TIER 2 flaw demands immediate patching for any digital public infrastructure relying on unified access management. |
| 5 | 1 | CVE-2026-81963 | TIER 1 Windows OS privilege escalation actively exploited in the wild, directly impacting government, healthcare, and financial infrastructure as a foundational platform risk. | A TIER 1 Windows Update Stack flaw is actively exploited in the wild, granting SYSTEM privileges with zero configuration barriers. For DPI operators, this underscores the critical need for immediate patching across government, healthcare, and financial estates running Windows 11/Server 2025. |
| 5 | 2 | CVE-2026-83941 | Core cloud identity provider (Microsoft Entra ID) missing authorization control enables tenant-wide privilege escalation, directly impacting Digital Identity infrastructure. | Microsoft Entra ID's missing authorization flaw (CVE-2026-83941) allows authorized users to hijack service principals and escalate privileges. A critical reminder for DPI and enterprise IdP admins to audit role assignments and apply the latest patches. |
| 4 | 2 | CVE-2026-12744 | Critical unauthenticated RCE in Ivanti Neurons for ITSM, a widely deployed enterprise and public-sector IT service management platform supporting government operations and internal infrastructure. | Unauthenticated RCE in Ivanti Neurons for ITSM poses a significant lateral movement risk for government and enterprise networks. While typically internal, misconfigurations or post-breach access could disrupt critical public-sector IT service delivery—prompt patching and network isolation are essential. |
| 4 | 2 | CVE-2026-58822 | Foundational mobile OS flaw with zero-interaction RCE, explicitly tied to national digital infrastructure and cross-sector endpoint risk. | A zero-interaction RCE in Android’s font renderer (CVE-2026-58822) highlights how foundational OS vulnerabilities can cascade across national digital infrastructure. With no workarounds available, regulated sectors must fast-track patching across mobile and IoT fleets. |
| 4 | 2 | CVE-2026-69276 | Critical unauthenticated RCE in core Windows OS libraries underpins enterprise and public-sector infrastructure, requiring immediate patching for internet-facing servers. | A critical, network-reachable RCE in Windows theming libraries (CVE-2026-69276) underscores the persistent risk to foundational OS infrastructure. With a CVSS of 9.8 and no authentication required, regulated and public sectors must prioritize patching internet-facing Windows servers to block initial access and lateral movement. |
| 4 | 2 | CVE-2026-69282 | TIER 2 RCE in Microsoft SharePoint Server, widely deployed in Government and public-sector citizen services; requires authentication but poses high risk to enterprise collaboration hubs. | Microsoft SharePoint Server faces a TIER 2 remote code execution risk (CVE-2026-69282) that threatens government portals and enterprise collaboration hubs. While authentication is required, the high impact on public-sector document management makes patching and MFA enforcement critical for DPI resilience. |
| 4 | 2 | CVE-2026-69291 | Unauthenticated network RCE in Windows Server/OS kernel, foundational infrastructure supporting all regulated and public-sector deployments. | A TIER 2 unauthenticated RCE in the Windows Volume Manager driver exposes internet-facing servers to immediate kernel compromise. Rapid patching and strict network segmentation are essential to protect foundational public and enterprise infrastructure. |
| 4 | 2 | CVE-2026-69334 | Core Windows OS kernel RCE impacting enterprise and public-sector infrastructure, requiring urgent patching for government and regulated environments. | Unauthenticated kernel RCE in Windows Volume Manager (CVE-2026-69334) poses a systemic risk to public-sector and enterprise infrastructure. Prioritize patching and network segmentation to protect critical government and regulated services. |
| 4 | 2 | CVE-2026-69338 | Foundational remote access infrastructure (RD Gateway) widely deployed in Government, Healthcare, and Finance sectors for secure administrative access. | Remote Desktop Gateway remains a critical bridge for public sector and regulated enterprise remote access. This TIER 2 privilege escalation flaw underscores why MFA, network segmentation, and timely patching are non-negotiable for protecting government and healthcare administrative workflows. |
| 4 | 2 | CVE-2026-69355 | TIER 2 RCE in Microsoft Exchange Server, foundational enterprise email infrastructure widely deployed across Government, Finance, and Healthcare sectors. | Microsoft Exchange Server remains a critical attack surface for regulated sectors. This TIER 2 RCE requires authentication but demands prompt patching for Government, Finance, and Healthcare deployments relying on Exchange for core communications. |
| 4 | 2 | CVE-2026-69380 | Foundational enterprise email infrastructure explicitly tied to government, finance, and healthcare deployments, enabling authenticated privilege escalation and organization-wide mailbox impersonation. | Microsoft Exchange Server faces a TIER 2 privilege escalation flaw that lets authenticated attackers impersonate any user and hijack organizational mailboxes. Critical for government, finance, and healthcare IT teams to patch promptly and enforce MFA to protect sensitive communications. |
| 4 | 2 | CVE-2026-69427 | Core Windows OS driver flaw impacting enterprise servers and workstations across all DPI sectors; requires authentication but enables high-impact privilege escalation. | A TIER 2 Windows driver vulnerability highlights the critical need for rigorous patching and least-privilege controls to secure the foundational infrastructure underpinning digital public services. |
| 4 | 2 | CVE-2026-69463 | Critical unauthenticated kernel RCE in Windows NTFS impacts foundational Government and Enterprise infrastructure, requiring immediate patching and SMB segmentation. | Windows NTFS just got a critical 9.8-rated kernel RCE (CVE-2026-69463). While no wild exploits are confirmed yet, government and enterprise IT teams must prioritize patching and lock down SMB traffic to prevent unauthenticated lateral movement. |
| 4 | 2 | CVE-2026-69465 | TIER 2 RCE in Microsoft SharePoint Server impacts government and public-sector IT stacks used for citizen services and internal collaboration. | Microsoft SharePoint Server faces a TIER 2 authorization bypass leading to RCE. While exploitation requires valid credentials, the flaw poses a significant risk to government agencies and public-sector deployments relying on SharePoint for citizen services and internal collaboration. Patch promptly and enforce strict access controls. |
| 4 | 2 | CVE-2026-69499 | Foundational Windows OS RCE impacting servers and endpoints across all regulated sectors and national digital infrastructure. | Unauthenticated RCE in Windows Imaging Component poses a systemic risk to national digital infrastructure. Prompt patching of Windows 10/11/Server is essential to secure public-facing and enterprise services. |
| 4 | 2 | CVE-2026-69503 | General infrastructure: foundational Windows OS/USB driver flaw impacting enterprise servers and domain controllers across all DPI sectors, enabling post-compromise privilege escalation. | A TIER 2 Windows USB driver flaw highlights the hidden risks in foundational OS layers: while gated by authentication, it offers attackers a fast track to SYSTEM-level control on domain controllers and enterprise servers. Patching and restricting RDP device redirection are critical for protecting DPI backends. |
| 4 | 2 | CVE-2026-69625 | Impacts foundational Windows OS components widely deployed in government and enterprise IT, enabling post-compromise privilege escalation across regulated environments. | A TIER 2 Windows telemetry flaw underscores the persistent risk of post-compromise privilege escalation in government and enterprise networks. Even with authentication barriers, unpatched foundational OS layers remain a critical vector for lateral movement—prioritize patching and network segmentation. |
| 4 | 2 | CVE-2026-69641 | Critical authenticated privilege escalation in Microsoft Exchange Server, a foundational communication platform explicitly tied to Government, Finance, and Healthcare sector resilience. | Microsoft Exchange remains a cornerstone of secure communications for government, finance, and healthcare. This TIER 2 privilege escalation flaw underscores why enforcing MFA and strict patch cycles is non-negotiable for protecting sensitive public and regulated data. |
| 4 | 2 | CVE-2026-69643 | Core Windows kernel driver flaw impacts foundational infrastructure across all DPI sectors (Identity, Healthcare, Finance, Government). | Windows Server and endpoint kernel vulnerabilities remain a critical attack vector for DPI environments. This TIER 2 flaw in the Storage Spaces driver underscores the need for rigorous patch management and least-privilege controls across government and regulated enterprise stacks. |
| 4 | 2 | CVE-2026-69669 | Foundational Windows kernel RCE affecting servers across all regulated sectors (Government, Finance, Healthcare, Identity) with unauthenticated network access. | A critical Windows kernel flaw (CVE-2026-69669) allows unauthenticated remote code execution across enterprise and cloud deployments. For DPI and regulated sectors, this underscores the urgent need for rapid patching and strict network segmentation. |
| 4 | 2 | CVE-2026-69730 | Foundational Windows DNS Server flaw underpins Active Directory deployments across government and regulated enterprise networks. | Unauthenticated RCE in Windows DNS Server poses a critical lateral movement risk for government and enterprise networks relying on Active Directory. Patching and network segmentation are essential to protect foundational digital infrastructure. |
| 4 | 2 | CVE-2026-69813 | TIER 2 unauthenticated RCE in Windows DNS Server, a foundational general infrastructure component explicitly tied to government and enterprise Active Directory deployments. | Internal DNS servers are often overlooked but remain prime targets for lateral movement. This TIER 2 Windows DNS flaw highlights why patching core infrastructure is critical for protecting government and enterprise networks from post-compromise escalation. |
| 4 | 2 | CVE-2026-69819 | Critical unauthenticated RCE in Windows RPC runtime directly impacts government and enterprise IT stacks that host digital public services. | CVE-2026-69819 enables unauthenticated remote code execution in Windows RPC, creating a high-risk lateral movement vector for government and enterprise networks. Immediate patching and network segmentation are essential to secure foundational DPI infrastructure. |
| 4 | 2 | CVE-2026-69829 | Foundational Windows OS vulnerability explicitly tied to Government, Finance, Healthcare, and Identity infrastructure deployments. | Unauthenticated RCE in Windows Shell poses a systemic risk to digital public infrastructure. Regulated sectors and government agencies should prioritize patching and network segmentation to secure foundational OS layers. |
| 4 | 2 | CVE-2026-69858 | Foundational Windows DNS Server RCE impacting enterprise and public-sector networks, underpinning identity, healthcare, finance, and government infrastructure. | Unauthenticated RCE in Windows DNS Server (CVE-2026-69858) poses a systemic risk to digital public infrastructure. As a foundational service for identity and directory resolution, exploitation could enable rapid lateral movement across government, healthcare, and financial networks. Patch immediately and enforce strict network segmentation. |
| 4 | 2 | CVE-2026-70342 | Foundational Windows kernel networking driver impacting enterprise, government, and critical infrastructure OS layers across all DPI sectors. | A network-reachable kernel privilege escalation in Windows AFD (CVE-2026-70342) underscores the need for rigorous patching and network segmentation across government and enterprise infrastructure. While no wild exploitation is confirmed, its universal deployment makes it a critical baseline risk for digital public services. |
| 4 | 2 | CVE-2026-72936 | Wormable, unauthenticated RCE in Windows SMB Client impacts foundational enterprise OS deployments across government, finance, and healthcare infrastructure. | A wormable, unauthenticated RCE in the Windows SMB Client (CVE-2026-72936) poses a lateral movement risk across enterprise networks. While not yet seen in the wild, its default-exploitable nature demands immediate SMB hardening and patching for all regulated infrastructure. |
| 4 | 2 | CVE-2026-73016 | Foundational Windows OS kernel vulnerability underpinning Government, Finance, Healthcare, and Identity infrastructure, requiring patching across regulated enterprise environments. | Windows Server and desktop environments across regulated sectors face a Tier 2 kernel privilege escalation risk. While local access is required, the ubiquitous deployment of Windows in public infrastructure makes timely Patch Tuesday updates critical for maintaining system integrity. |
| 4 | 2 | CVE-2026-73018 | Core Windows OS font rendering vulnerability enables RCE on servers and workstations, directly impacting the foundational infrastructure supporting government, finance, and healthcare digital services. | CVE-2026-73018 introduces a critical RCE risk in the Windows font engine, affecting servers and workstations across regulated sectors. Though exploitation requires a crafted file, prompt patching is essential to protect the foundational OS layer underpinning digital public infrastructure. |
| 4 | 2 | CVE-2026-73309 | Directly impacts Digital Identity infrastructure by bypassing OAuth2/PKCE token validation, undermining core authentication and access control mechanisms. | A critical OAuth2 bypass in XenForo lets attackers swap authorization codes for access tokens without client secrets or PKCE verification. For DPI and regulated platforms relying on standard identity protocols, this underscores the need to harden token endpoints and enforce strict credential validation. |
| 4 | 2 | CVE-2026-73313 | Digital Identity: MFA bypass in WebAuthn/passkey authentication flow compromises identity verification and account security in public-facing web platforms. | A critical MFA bypass in XenForo allows attackers to hijack accounts using their own passkeys, highlighting the risks of flawed WebAuthn implementations in community and enterprise forums. Patch to 2.3.13 immediately. |
| 4 | 2 | CVE-2026-75746 | Enterprise application server widely deployed in government, finance, and healthcare; critical RCE risk for legacy systems. | Adobe ColdFusion remains a critical backbone for many government and healthcare legacy systems. This TIER 2 SQL injection vulnerability underscores the ongoing risk of unpatched enterprise middleware—patch now to protect sensitive citizen and patient data. |
| 4 | 2 | CVE-2026-75998 | Unauthenticated file read in Adobe ColdFusion impacts Government and Finance legacy backend services, risking exposure of citizen data and financial records. | Legacy enterprise stacks like Adobe ColdFusion remain critical in Government and Finance sectors. This unauthenticated file read vulnerability highlights the need for rigorous patching and perimeter controls to protect sensitive citizen and financial data. |
| 4 | 2 | CVE-2026-76200 | Stored XSS in Adobe Commerce/Magento enables session takeover on public-facing e-commerce portals, directly impacting Finance sector payment and transaction operations. | E-commerce platforms handling public payments are prime targets for session hijacking. This TIER 2 stored XSS in Adobe Commerce/Magento underscores the need for strict input validation and CSP headers to protect financial transactions and customer accounts. |
| 4 | 2 | CVE-2026-76201 | Stored XSS in Adobe Commerce/Magento enables session hijacking and threatens payment processing integrity, directly impacting the Finance sector and PCI-DSS compliance. | A critical stored XSS flaw in Adobe Commerce and Magento could let attackers hijack sessions and compromise payment data across internet-facing storefronts. For Finance and regulated commerce, patching is urgent to protect transaction integrity and meet PCI-DSS standards. |
| 4 | 2 | CVE-2026-76202 | Finance sector impact: unauthenticated privilege escalation in Adobe Commerce/Magento exposes payment processing, customer accounts, and transaction data on public-facing e-commerce infrastructure. | Unauthenticated privilege escalation in Adobe Commerce/Magento threatens Finance DPI by risking exposure of payment data and customer accounts on internet-exposed storefronts. Apply September 2026 patches immediately to secure transaction infrastructure. |
| 4 | 2 | CVE-2026-77108 | Unauthenticated authorization bypass in widely deployed e-commerce platforms exposes customer accounts and transaction data, directly impacting Finance sector operations and payment processing integrity. | Public-facing e-commerce platforms face a critical unauthenticated authorization flaw that could expose customer accounts and transaction data. Finance and retail operators should prioritize patching to protect payment processing integrity and comply with data protection standards. |
| 4 | 2 | CVE-2026-77109 | Unauthenticated privilege escalation in Adobe Commerce B2B directly threatens financial transaction integrity and payment processing systems, aligning with the Finance DPI sector. | Public-facing e-commerce portals are prime targets for unauthenticated privilege escalation. CVE-2026-77109 in Adobe Commerce B2B bypasses authorization controls by default, risking financial data and transaction integrity—patching is critical for regulated commerce environments. |
| 4 | 2 | CVE-2026-77111 | TIER 2 authorization bypass in Adobe Commerce/Magento threatens payment processing and transaction integrity in Finance-sector e-commerce infrastructure. | E-commerce platforms underpin modern digital finance, but a TIER 2 authorization flaw in Adobe Commerce/Magento could let compromised admin accounts bypass critical security controls. Patching and enforcing MFA on high-privilege accounts are essential to protect transaction integrity and customer data. |
| 4 | 2 | CVE-2026-77493 | Foundational Windows OS RCE impacting internet-facing servers that underpin government, finance, and healthcare digital services. | Unauthenticated network RCE in Microsoft Windows (CVE-2026-77493) threatens internet-facing servers that form the backbone of regulated and public-sector infrastructure. Immediate patching of Windows 10/11/Server is critical to safeguard foundational DPI environments. |
| 4 | 2 | CVE-2026-77774 | Unauthenticated authorization bypass in widely deployed e-commerce platforms exposes payment data and customer accounts, directly impacting the Finance DPI sector. | A TIER 2 flaw in Adobe Commerce/Magento allows unauthenticated attackers to bypass authorization and read sensitive payment and customer data. With no wild exploits yet but zero deployment barriers, Finance and regulated commerce teams should prioritize patching before automated scanners take advantage. |
| 4 | 2 | CVE-2026-78449 | Foundational Windows OS kernel vulnerability enabling unauthenticated RCE; impacts Government, Finance, and Healthcare infrastructure via widespread enterprise deployment. | Windows Server and desktop environments face a critical unauthenticated RCE risk via the RMCAST driver. As foundational infrastructure for public and regulated sectors, patching is essential to prevent lateral movement and domain compromise. |
| 4 | 2 | CVE-2026-81349 | General infrastructure flaw in Azure HDInsights that underpins critical data workloads for Finance, Healthcare, and Government sectors. | Cloud data platforms like Azure HDInsights form the backbone of regulated sector workloads. This TIER 2 command injection flaw highlights why strict IAM, network segmentation, and patching remain non-negotiable for DPI environments handling sensitive public and financial data. |
| 4 | 2 | CVE-2026-83992 | Core Windows OS component enabling unauthenticated RCE, explicitly flagged as foundational to government and national digital infrastructure deployments. | Windows remains the backbone of government and public-sector IT, making CVE-2026-83992 a critical watch item for DPI operators. While no wild exploitation is confirmed, this unauthenticated RCE in the Windows Imaging Component underscores the need for disciplined patching and network segmentation across national infrastructure. |
| 4 | 2 | CVE-2026-86464 | Hardcoded default credentials in a Keycloak-based Identity Manager enable full IdP compromise, directly impacting the Digital Identity sector and credential/token management. | Default credentials in a Keycloak-based identity provider can hand attackers full control over user accounts, roles, and signing keys. For any organization deploying IdAM on Kubernetes, this highlights why secret management and secure defaults are non-negotiable for digital identity infrastructure. |
| 3 | 2 | CVE-2026-19651 | General-purpose Java web framework with authorization bypass impacting enterprise, government, finance, and healthcare applications deployed as public-facing services. | A high-complexity authorization bypass in IBM's Quarkus framework highlights the hidden risks in foundational web stacks. While exploitation requires specific extension usage, regulated sectors relying on Quarkus for citizen or financial services should prioritize patching to prevent unauthorized data access. |
| 3 | 2 | CVE-2026-55007 | Core enterprise email infrastructure with unauthenticated RCE, explicitly tied to supporting government and finance operations. | Unauthenticated RCE in Microsoft Exchange Server threatens government and financial institutions relying on on-premises email. Patch OWA/ECP endpoints immediately to block lateral movement and data exfiltration. |
| 3 | 2 | CVE-2026-58240 | Critical SAP NetWeaver Message Server flaw enables unauthenticated RCE across enterprise clusters, impacting regulated finance, healthcare, and government deployments reliant on SAP for core operations. | SAP environments face a critical missing-authentication flaw (CVE-2026-58240) allowing unauthenticated RCE across application clusters. While typically internal-facing, this vulnerability poses severe compliance and operational risks for finance, healthcare, and government sectors running SAP NetWeaver. |
| 3 | 2 | CVE-2026-68827 | Foundational Windows OS privilege escalation impacting enterprise and government IT stacks, enabling SYSTEM-level access for authenticated attackers. | CVE-2026-68827 exposes a network-reachable privilege escalation in Windows GDI+ that threatens enterprise and government infrastructure. While it requires valid credentials, the high impact on core OS components makes immediate patching and least-privilege enforcement essential for DPI environments. |
| 3 | 2 | CVE-2026-69397 | Foundational Windows remote administration service underpinning government, finance, and healthcare infrastructure deployments. | A TIER 2 RCE in Microsoft OpenSSH for Windows highlights the persistent risk in foundational remote access layers. Even as an optional feature, its widespread use across public and enterprise server fleets makes prompt patching and strict network segmentation critical for DPI resilience. |
| 3 | 2 | CVE-2026-69438 | Foundational Windows OS component widely deployed in enterprise and government environments, posing RCE risk to legacy web services and internal infrastructure. | Legacy Windows scripting engines remain a critical attack surface for government and enterprise infrastructure. CVE-2026-69438 highlights the need to patch or disable JScript in IIS and internal networks to prevent remote code execution. |
| 3 | 2 | CVE-2026-69496 | Foundational Windows OS vulnerability impacting servers and file shares across government, finance, and healthcare DPI deployments. | CVE-2026-69496 introduces a critical RCE risk in Windows Compressed Folder, threatening the foundational OS layer of digital public infrastructure. Regulated sectors should prioritize patching and restrict untrusted archive processing over SMB. |
| 3 | 2 | CVE-2026-69514 | General infrastructure / Government: Foundational Windows RDS flaw impacting public-sector remote access and telework channels, requiring strict patching and access controls. | Windows Remote Desktop Services underpins critical government and enterprise remote operations. This TIER 2 RCE vulnerability reinforces the need for NLA enforcement, network segmentation, and timely patching across public-sector IT environments. |
| 3 | 2 | CVE-2026-69525 | Foundational Windows Server/RDS remote access layer underpins government, healthcare, and financial enterprise environments, making unauthenticated RCE a critical infrastructure risk. | Unauthenticated RCE in Windows Remote Desktop Services (CVE-2026-69525) poses a systemic risk to public and regulated sector infrastructure. While no wild exploitation is confirmed, the critical CVSS 9.8 score and default network exposure demand immediate patching and strict RDP segmentation for DPI operators. |
| 3 | 2 | CVE-2026-69586 | Foundational Windows OS RCE impacting government and enterprise infrastructure, requiring immediate patching and GPO hardening. | Critical unauthenticated RCE in Windows PDF handling poses a lateral movement risk for government and enterprise networks. Patch promptly and enforce ASR rules to secure foundational infrastructure. |
| 3 | 2 | CVE-2026-69588 | General infrastructure risk: unauthenticated remote DoS in Windows TCP/IP stack threatens availability of foundational government, finance, and healthcare server deployments. | Windows Server and client TCP/IP stacks face a new unauthenticated DoS risk (CVE-2026-69588). While no wild exploitation is confirmed, the broad attack surface on core OS networking demands prompt patching to protect critical public and enterprise services. |
| 3 | 2 | CVE-2026-69597 | Core Windows HTTP.sys kernel flaw impacts widely deployed enterprise servers and workstations across all DPI deployments, requiring standard patching. | Windows Server and 11 administrators should prioritize patching this HTTP.sys privilege escalation flaw. While authentication is required, it poses a significant lateral movement risk across government and enterprise infrastructure. |
| 3 | 2 | CVE-2026-69769 | Foundational Windows OS flaw enabling unauthenticated internal RCE, directly impacting the general infrastructure layer that underpins government, finance, and healthcare digital services. | Unauthenticated RCE in Windows Print Spooler (CVE-2026-69769) poses a high lateral-movement risk across internal enterprise and government networks. Patching and network segmentation are critical to protect foundational digital infrastructure. |
| 3 | 2 | CVE-2026-72940 | TIER 2 RCE in Windows Schannel TLS stack impacts foundational infrastructure securing government, finance, and healthcare transport layers. | A TIER 2 remote code execution flaw in Windows Schannel exposes internet-facing TLS services to unauthenticated attacks. Critical for patching government and enterprise servers relying on default Windows TLS configurations. |
| 3 | 2 | CVE-2026-72959 | General infrastructure risk: Windows RRAS/VPN gateways are foundational for remote access across government, finance, and healthcare deployments. | TIER 2 unauthenticated RCE in Windows RRAS threatens internet-facing VPN endpoints widely used by public and regulated sectors. Immediate patching and port restriction are essential to secure remote access infrastructure. |
| 3 | 2 | CVE-2026-72981 | Core Windows OS networking flaw enables unauthenticated RCE, impacting foundational infrastructure across government, finance, and healthcare deployments. | Unauthenticated RCE in Windows IP Helper (CVE-2026-72981) poses a systemic risk to digital public infrastructure. As a foundational OS component, this TIER 2 flaw requires immediate patching across regulated networks to prevent lateral movement and ransomware deployment. |
| 3 | 2 | CVE-2026-72983 | Foundational Windows OS/Server infrastructure for government and enterprise; unauthenticated RCE in ICS risks backend hosting environments. | CVE-2026-72983 introduces a critical unauthenticated RCE in Windows Internet Connection Sharing (ICS) across Windows 10, 11, and Server versions. With a CVSS of 9.8 and no user interaction required, this vulnerability underscores the need for rapid patching and network segmentation in government and enterprise digital infrastructure. |
| 3 | 2 | CVE-2026-72986 | TIER 2 unauthenticated network RCE in Windows OS underpins critical general infrastructure for government, finance, and healthcare deployments. | A TIER 2 network RCE in Windows Graphic Fonts highlights the persistent risk to foundational OS layers. Even without active wild exploitation, unauthenticated remote code execution demands immediate patching across all regulated and public-facing Windows environments. |
| 3 | 2 | CVE-2026-73013 | General infrastructure flaw in Windows OS impacting broad enterprise and public-sector IT environments uniformly. | A critical RCE in the Windows Imaging Component (CVE-2026-73013) threatens foundational public-sector and enterprise infrastructure. Ensure immediate patching for any service handling external image data. |
| 3 | 2 | CVE-2026-73310 | OAuth2 token theft via redirect URI bypass directly impacts identity and access management flows, aligning with the Digital Identity sector. | As community platforms integrate deeper with enterprise SSO and OAuth2 flows, this redirect URI bypass underscores the critical need for strict token binding in public-facing identity integrations. |
| 3 | 2 | CVE-2026-73314 | Finance: bypasses PayPal payment validation in public-facing platforms, impacting transaction integrity and revenue. | Payment gateways in community platforms aren't immune to logic flaws. CVE-2026-73314 shows how a misconfigured webhook can bypass PayPal signature checks, risking fraudulent transactions and revenue loss for operators. |
| 3 | 2 | CVE-2026-81352 | Core Windows OS component affecting general enterprise and public infrastructure uniformly, requiring coordinated patching across regulated environments. | A Tier 2 Windows OS vulnerability (CVE-2026-81352) enables unauthenticated RCE via crafted media files. Though not yet exploited, its default deployment across public infrastructure demands immediate patching to protect DPI endpoints. |
| 2 | 2 | CVE-2026-69539 | Foundational Windows RDS remote access infrastructure explicitly noted for public-sector and enterprise deployment, requiring immediate patching and MFA enforcement. | Critical RCE in Windows Remote Desktop Services (CVE-2026-69539) highlights the need for rapid patching and strict MFA in public-sector and enterprise environments. While authentication is required, unpatched RDS endpoints remain a high-value target for lateral movement. |
| 2 | 2 | CVE-2026-73315 | Finance sector relevance via PayPal payment processing component vulnerability impacting transaction integrity and payment gateway security. | Unauthenticated SSRF in XenForo's PayPal webhook handler exposes payment processing to internal network scanning and cloud metadata theft. Forum admins using PayPal integrations should patch immediately to protect transaction security. |
| 2 | 2 | CVE-2026-77089 | Tier 2 enterprise backup infrastructure vulnerability; unauthenticated API bypass threatens data integrity and availability for regulated sector deployments. | Backup infrastructure underpins every regulated digital service. This unauthenticated API bypass in Commvault Command Center underscores why network segmentation and rapid patching are non-negotiable for protecting critical data protection systems. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-11573.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12611.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12648.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12745.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16025.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18851.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19201.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19232.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33389.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-34223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53581.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57099.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58599.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58600.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58823.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62648.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62649.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62697.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62744.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62813.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66819.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66820.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67368.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67373.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67379.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67380.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67381.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67384.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67388.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67631.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67636.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67638.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67642.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68828.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68834.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68841.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68875.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68884.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68887.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68889.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69265.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69270.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69272.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69274.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69277.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69279.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69280.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69283.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69284.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69289.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69296.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69311.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69312.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69323.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69331.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69341.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69347.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69348.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69358.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69359.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69362.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69364.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69365.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69368.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69377.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69379.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69386.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69388.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69389.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69391.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69398.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69401.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69407.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69420.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69421.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69423.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69424.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69426.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69429.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69433.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69436.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69439.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69440.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69443.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69444.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69447.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69458.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69466.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69468.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69470.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69472.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69473.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69475.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69476.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69478.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69479.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69480.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69481.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69482.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69485.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69488.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69495.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69500.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69501.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69510.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69512.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69516.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69517.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69522.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69528.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69529.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69530.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69532.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69534.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69535.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69536.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69538.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69542.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69544.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69547.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69549.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69553.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69556.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69560.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69561.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69564.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69567.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69571.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69573.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69578.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69580.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69581.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69582.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69589.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69592.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69593.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69595.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69598.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69600.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69601.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69602.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69603.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69604.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69605.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69606.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69607.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69608.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69610.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69611.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69613.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69614.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69617.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69619.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69620.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69631.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69632.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69638.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69648.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69654.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69681.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69685.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69686.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69731.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69732.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69735.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69742.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69784.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69797.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69820.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69834.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69838.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69841.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69859.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69875.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69889.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69891.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69921.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70283.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70562.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70564.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70565.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70567.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70568.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70569.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70570.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70573.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70578.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70581.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70586.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71342.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71343.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71345.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71351.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72923.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72926.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72928.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72957.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72962.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72973.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72982.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72989.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72991.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72993.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72997.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73001.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73006.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73011.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73012.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73015.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73020.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73021.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73022.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73023.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73024.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73028.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75156.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75993.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76191.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76561.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77097.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77098.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77102.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77103.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77106.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77480.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77481.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77482.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77483.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77485.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77487.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77495.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77500.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77503.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77504.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77886.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77889.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77899.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77968.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78234.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78439.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78444.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78447.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78457.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78461.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78504.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78507.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78510.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78511.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78512.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78514.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78517.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78518.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78519.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78524.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78525.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80074.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80080.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80081.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80085.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80097.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81379.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81386.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81388.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81389.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81396.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81397.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81398.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81957.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81960.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81983.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81992.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81994.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82053.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82057.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82061.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82062.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82065.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82067.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82070.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82071.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82073.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82074.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82536.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83940.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83968.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83973.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83974.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83978.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83981.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83982.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83983.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83986.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83987.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83988.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83990.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83997.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83998.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84387.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85400.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85982.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85983.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86081.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86135.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86600.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86733.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86806.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-67376.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-69342.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-69384.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-69744.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-69760.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-69809.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-70065.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-77494.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-77498.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-77501.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-77502.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-77890.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-77893.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-77895.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-82054.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-82055.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-83989.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-84001.md` — heuristic TIER 3/4
