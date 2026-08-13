# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-13 21:40:06Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-11`
- **Included count:** 47

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-10579 | Critical SAML authentication bypass in Red Hat JBoss EAP enables arbitrary role assumption, directly impacting Digital Identity and enterprise federation infrastructure. | A critical, zero-barrier SAML flaw in Red Hat JBoss EAP lets attackers forge assertions and impersonate any user without credentials. For DPI and enterprise SSO deployments, this underscores the urgent need to patch federation endpoints and restrict unsolicited SAML responses. |
| 5 | 2 | CVE-2026-15556 | Directly compromises SAML 2.0 federated identity management, enabling unauthenticated authentication bypass and role forgery in enterprise and public-sector SSO deployments. | A critical SAML 2.0 signature validation flaw in Red Hat JBoss EAP allows unauthenticated attackers to forge identities and bypass authentication entirely. Organizations relying on federated SSO for citizen or enterprise access should prioritize patching to prevent full account takeover. |
| 5 | 2 | CVE-2026-49179 | TIER 2 command injection in Windows Active Directory directly compromises core IdAM authentication, authorization, and credential storage, posing a severe lateral movement risk to digital identity infrastructure. | A TIER 2 command injection in Windows Active Directory (CVE-2026-49179) could grant unauthenticated RCE on Domain Controllers, threatening the authentication and credential foundations of enterprise and government digital identity systems. Patching and strict network segmentation remain critical for IdAM resilience. |
| 5 | 2 | CVE-2026-62785 | Directly impacts Digital Identity and Government/Finance sectors via unauthenticated RCE in Windows LDAP, a foundational Active Directory and IdAM component. | CVE-2026-62785 delivers unauthenticated RCE in Windows LDAP, threatening the Digital Identity backbones of government and financial institutions. Immediate patching and strict LDAP port segmentation are critical to safeguard Active Directory and prevent enterprise-wide compromise. |
| 5 | 2 | CVE-2026-62795 | Unauthenticated RCE in Windows LDAP/Active Directory directly compromises core Digital Identity and Government authentication infrastructure. | CVE-2026-62795 enables unauthenticated remote code execution in Windows LDAP, a critical lateral movement vector for enterprise and government identity systems. Immediate patching and strict network segmentation are vital to protect core authentication services. |
| 5 | 2 | CVE-2026-62869 | Digital Identity: Compromises token integrity and session verification in Microsoft Entra ID, a foundational cloud IdAM platform underpinning SSO and zero-trust architectures. | A TIER 2 vulnerability in Microsoft Entra ID allows authorized attackers to spoof identity tokens and session data, directly threatening the integrity of SSO and zero-trust frameworks. Organizations relying on cloud IdAM should prioritize patching and enforce strict conditional access to protect trust boundaries. |
| 5 | 2 | CVE-2026-62911 | Authentication bypass in Microsoft Exchange Server disrupts enterprise identity and session management, directly impacting Digital Identity, Government, Finance, and Healthcare infrastructure. | Microsoft Exchange Server faces a high-severity authentication bypass (CVE-2026-62911) that allows credential replay for privilege escalation. Public sector and regulated enterprises should prioritize August 2026 patches and enforce MFA/conditional access to protect foundational identity and email workflows. |
| 5 | 1 | CVE-2026-68820 | Foundational Windows kernel flaw actively exploited by APTs, directly threatening the operational resilience of all government, finance, and healthcare services running on Windows infrastructure. | A TIER 1 Windows kernel vulnerability is being actively weaponized by the Lazarus Group, granting SYSTEM privileges to any local user. For DPI operators, this underscores the non-negotiable need for immediate patching across all Windows endpoints and servers to protect critical public services. |
| 5 | 2 | CVE-2026-69102 | Critical authentication bypass in an open-source IAM/SSO platform via a hard-coded JWT secret, directly threatening Digital Identity infrastructure and downstream regulated sectors. | A hard-coded JWT secret in a widely deployed open-source IAM platform allows trivial admin impersonation. For DPI operators, this underscores the critical need to audit default credentials in identity gateways before they become a single point of failure for citizen and enterprise access. |
| 5 | 2 | CVE-2026-72534 | Digital Identity sector: core open-source IdP (Authentik) flaw enables full administrative takeover via SCIM token abuse, compromising authentication and authorization anchors. | A TIER 2 flaw in Authentik lets attackers with a stolen SCIM token hijack admin groups and take over the entire Identity Provider. For any org relying on open-source IdAM for SSO, this underscores the critical need for strict token scoping and immediate patching. |
| 5 | 2 | CVE-2026-72537 | TIER 2 privilege escalation in Authentik IdP allows SCIM token abuse to hijack superuser accounts, compromising SSO and downstream identity services. | Identity providers are the crown jewels of digital infrastructure. CVE-2026-72537 in Authentik shows how a scoped SCIM token flaw can escalate to full IdP takeover, risking every connected SSO service. Patch and audit token scopes now. |
| 5 | 2 | CVE-2026-72561 | TIER 2 broken access control in Peppermint helpdesk allows authenticated users to hijack global OIDC/SSO settings, enabling mass credential harvesting (Digital Identity). | A TIER 2 flaw in the Peppermint helpdesk system lets any logged-in user hijack global SSO/OIDC settings, turning a single compromised account into a mass credential harvester. Critical for any organization relying on self-hosted ticketing with federated identity. |
| 5 | 2 | CVE-2026-73086 | Digital Identity: Corrupts CSPRNG pool in widely used JS library, rendering session and CSRF tokens deterministic and enabling authentication bypass. | A single integer overflow in a popular JS library can turn unpredictable session tokens into predictable strings, opening the door to mass account takeovers. Critical patch for any platform relying on robust digital identity and session management. |
| 4 | 2 | CVE-2016-20097 | TIER 2 unauthenticated SQLi in Weaver E-cology OA platform, widely deployed in Chinese government agencies and state-owned enterprises for internal collaboration and sensitive data handling. | Legacy OA platforms remain a prime target for state and enterprise networks. This unauthenticated SQLi in Weaver E-cology enables trivial credential theft and file exfiltration, highlighting the risks of internet-exposed internal collaboration tools in government deployments. |
| 4 | 2 | CVE-2026-15565 | Directly impacts Red Hat Single Sign-On and JBoss EAP middleware, disrupting authentication and session management services critical to digital identity infrastructure. | A TIER 2 DoS flaw in Undertow could knock out Red Hat SSO and JBoss EAP instances, disrupting authentication flows for enterprise and public-sector identity providers. Apply the provided XML workarounds or patch promptly to maintain service availability. |
| 4 | 2 | CVE-2026-20702 | Foundational cloud infrastructure flaw compromising Intel DCAP attestation integrity, directly impacting hardware-rooted trust for regulated Finance, Healthcare, and Government workloads. | Intel DCAP attestation flaw (CVE-2026-20702) undermines hardware-rooted trust in cloud data centers. While requiring specialized knowledge to exploit, it poses a systemic risk to secure enclaves underpinning regulated Finance, Healthcare, and Government services. Patch to v1.25+ and restrict network access. |
| 4 | 2 | CVE-2026-48416 | Unauthenticated authorization bypass in widely deployed e-commerce platforms directly impacts the Finance sector by exposing payment, transaction, and customer financial data. | Unauthenticated data access in major e-commerce platforms poses a direct threat to financial data integrity and regulatory compliance. Organizations processing payments must prioritize the August 2026 patch to secure transaction endpoints and maintain customer trust. |
| 4 | 2 | CVE-2026-58231 | Unauthenticated RCE in SAP Commerce Cloud's Data Hub Adapter directly impacts Finance sector digital infrastructure by compromising payment processing and transactional workflows. | Critical unauthenticated RCE in SAP Commerce Cloud exposes enterprise e-commerce and payment gateways to full takeover. Finance and retail sectors should prioritize patching and network segmentation to protect transactional integrity. |
| 4 | 2 | CVE-2026-62878 | Critical unauthenticated RCE in Windows DNS Server, a foundational networking component widely deployed in government and public sector IT environments. | Unpatched Windows DNS servers face critical remote code execution risks, threatening the backbone of government and enterprise networks. Prioritize patching authoritative and internal DNS infrastructure to protect public digital services from systemic compromise. |
| 4 | 2 | CVE-2026-62913 | Foundational enterprise email infrastructure explicitly underpinning Government, Finance, and Healthcare operations; requires prompt patching to secure regulated communications. | Microsoft Exchange Server remains a critical backbone for government, financial, and healthcare communications. This TIER 2 RCE flaw highlights why enforcing MFA and rapid patching is non-negotiable for protecting regulated enterprise environments. |
| 4 | 2 | CVE-2026-65663 | Foundational enterprise collaboration platform explicitly tied to Government, Healthcare, and Finance deployments for sensitive document management and internal portals. | Microsoft SharePoint RCE (CVE-2026-65663) demands priority patching for regulated sectors. While it requires valid credentials, compromised accounts can lead to full server takeover across critical Gov, Health, and Finance document repositories—enforce MFA, segment portals, and apply August 2026 updates. |
| 4 | 2 | CVE-2026-65789 | Foundational Windows DNS RCE vulnerability explicitly tied to all DPI sectors (Identity, Healthcare, Finance, Government) and critical national infrastructure. | Unauthenticated RCE in Windows DNS poses a systemic risk to digital public infrastructure, enabling lateral movement and service disruption across government, finance, and healthcare networks. Prioritize patching and network segmentation to protect foundational naming services. |
| 4 | 2 | CVE-2026-67568 | Hard-coded credentials in a fertility tracking app expose sensitive reproductive health data via a public cloud API, directly impacting the Healthcare sector. | Hard-coded API keys in a consumer fertility app grant unauthenticated access to sensitive reproductive health records. A stark reminder that health-tech platforms must treat clinical data with enterprise-grade security controls. |
| 4 | 2 | CVE-2026-68067 | Critical authentication bypass in a medical IoT cloud API enabling full account takeover, directly impacting Healthcare data privacy and Digital Identity/session management. | A trivial authentication flaw in a medical hormone monitor’s cloud API allows attackers to hijack accounts with just an email address, highlighting the urgent need for robust identity controls in connected healthcare devices. As medical IoT expands, securing patient data at the API layer is no longer optional—it’s a clinical safety imperative. |
| 4 | 2 | CVE-2026-71331 | Impacts Digital Identity and Government sectors by compromising Azure Attestation and Device Health Attestation services, which underpin zero-trust device validation, MDM compliance, and secure access to public infrastructure. | Unauthenticated RCE in Windows Device Health Attestation services threatens the trust chains underpinning zero-trust and government MDM deployments. Patching and internal network segmentation are critical to protect digital identity validation pipelines. |
| 4 | 2 | CVE-2026-71362 | Unauthenticated privilege escalation in widely deployed e-commerce platforms directly impacts the Finance sector by exposing payment processing, customer accounts, and transaction data. | Unauthenticated privilege escalation in Adobe Commerce/Magento poses a direct threat to the Finance sector, exposing payment gateways and customer accounts to automated attacks. With zero authentication barriers and high CVSS scores, regulated e-commerce operators must prioritize patching within the standard 30–60 day window. |
| 4 | 2 | CVE-2026-72536 | Directly impacts the Finance sector by enabling unauthenticated manipulation of Stripe payment intents and tenant billing via a public-facing GraphQL API. | Unauthenticated GraphQL mutations in customer engagement platforms can bypass payment controls, exposing organizations to direct financial fraud. Patching missing auth checks on billing endpoints is critical for protecting digital transaction integrity. |
| 4 | 2 | CVE-2026-72544 | Unauthenticated audit-trail forgery in a widely deployed e-signature platform undermines legal non-repudiation and compliance for public and regulated digital transactions. | CVE-2026-72544 allows unauthenticated attackers to forge audit logs in OpenSign, directly threatening the legal validity of digitally signed contracts and government services. Patch now to preserve non-repudiation and regulatory compliance in your DPI stack. |
| 4 | 2 | CVE-2026-72545 | Unauthenticated IDOR in a widely deployed e-signature platform directly compromises contact data integrity for government citizen services and financial contract workflows. | Public-facing e-signature platforms are critical for digital government services and financial agreements, but an unauthenticated flaw in OpenSign allows attackers to silently overwrite contact records. Organizations relying on digital contracts should patch immediately to prevent business email compromise and service disruption. |
| 4 | 2 | CVE-2026-72548 | Unauthenticated tenant configuration disclosure in a default-public e-signature platform widely used for government procurement and citizen digital contracts. | E-signature platforms are foundational to modern digital government services. This unauthenticated flaw in OpenSign exposes tenant configurations by default, underscoring the critical need for strict API authorization in public-facing citizen and procurement portals. |
| 4 | 2 | CVE-2026-72600 | Unauthenticated access control flaw in an ERP/CRM system exposes customer invoices and financial transaction records, directly impacting the Finance DPI sector. | Unauthenticated API endpoints in business ERP systems can turn routine invoice downloads into mass financial data breaches. For Finance and regulated sectors, this TIER 2 flaw highlights why middleware hardening and reverse proxy controls are non-negotiable for exposed accounting platforms. |
| 4 | 2 | CVE-2026-72609 | TIER 2 authenticated SQLi in Koha library systems exposes patron PII and staff credentials, directly impacting government/public sector data protection obligations. | Public libraries are critical civic infrastructure. This TIER 2 SQL injection in Koha could expose patron PII and staff credentials, highlighting the need for strict access controls and timely patching in government-facing digital services. |
| 4 | 2 | CVE-2026-72921 | JWT authorization bypass in multi-tenant storage enables cross-tenant data access, impacting Digital Identity and regulated data lake deployments. | Multi-tenant data lakes relying on JWT scoping face cross-tenant breach risks due to naive prefix matching. Upgrade SeaweedFS or enforce strict path separators to protect tenant isolation. |
| 4 | 2 | CVE-2026-73160 | Unauthenticated SSRF in cti-transmute, a threat intelligence conversion service widely deployed by government CSIRTs and national cybersecurity operations centers. | National cybersecurity operations and government CSIRTs rely on MISP/cti-transmute for threat intel sharing. This unauthenticated SSRF allows anonymous attackers to probe internal networks, highlighting the need to patch public-facing threat intel infrastructure. |
| 3 | 2 | CVE-2026-20349 | Foundational perimeter firewall/VPN infrastructure with active in-wild exploitation and CISA KEV status, critical for maintaining remote access availability in regulated and public-sector environments. | Active exploitation of Cisco ASA/FTD SSL VPNs (CVE-2026-20349) has been added to the CISA KEV catalog, posing a direct availability risk to government and enterprise remote access. With no workaround available, immediate patching of perimeter firewalls is essential to protect critical digital infrastructure. |
| 3 | 2 | CVE-2026-48415 | TIER 2 authorization bypass in Adobe Commerce/Magento impacts widely deployed e-commerce platforms processing financial transactions and customer data, aligning with Finance and General Infrastructure DPI sectors. | E-commerce platforms underpin modern digital commerce and financial workflows. This TIER 2 authorization flaw in Adobe Commerce/Magento highlights the need for strict access controls and timely patching in transaction-facing infrastructure. |
| 3 | 2 | CVE-2026-50516 | Critical unauthenticated privilege escalation in Azure Kubernetes Service control plane, impacting foundational cloud infrastructure hosting regulated and public-sector workloads. | Unauthenticated privilege escalation in Azure Kubernetes Service (AKS) control plane highlights the risks of default cloud configurations. Organizations hosting regulated workloads must enforce private clusters and apply patches immediately to protect foundational infrastructure. |
| 3 | 2 | CVE-2026-62781 | Foundational Windows OS RCE impacting enterprise and government server workloads; requires standard patching for general infrastructure resilience. | Windows RPC RCE (CVE-2026-62781) hits core OS components across enterprise and government servers. While exploitation requires unusual conditions, patching remains critical for foundational infrastructure resilience. |
| 3 | 2 | CVE-2026-62792 | Core Windows TCP/IP stack RCE affects foundational server infrastructure underpinning government, finance, and healthcare digital services. | A TIER 2 Windows TCP/IP stack vulnerability enables unauthenticated kernel RCE, reminding DPI operators that foundational OS networking components require immediate patching across all regulated server environments. |
| 3 | 2 | CVE-2026-62815 | Critical unauthenticated RCE in core Windows Server transport layer (MsQuic) underpins network infrastructure for government, finance, and healthcare digital services. | A critical, unauthenticated RCE in Microsoft’s QUIC transport layer highlights the hidden attack surface in modern Windows Server deployments. While not exploited in the wild, internet-facing servers running HTTP/3 or SMB over QUIC require immediate patching to protect foundational public and enterprise infrastructure. |
| 3 | 2 | CVE-2026-62817 | TIER 2 RCE in Windows DNS Server impacts foundational internal networking infrastructure widely deployed across government, finance, and healthcare enterprise environments. | A critical internal RCE in Windows DNS Server (CVE-2026-62817) highlights the persistent risk to foundational enterprise infrastructure. While not internet-facing by default, adjacent-network exploitation can enable rapid lateral movement across regulated digital public services. |
| 3 | 2 | CVE-2026-62823 | Foundational Windows DHCP Server RCE impacts internal network operations across all regulated sectors and public infrastructure. | Unauthenticated RCE in Windows DHCP Server (CVE-2026-62823) poses a high lateral movement risk for enterprise and public networks. Patching and strict UDP 67/68 segmentation are critical to protect foundational infrastructure. |
| 3 | 2 | CVE-2026-62898 | Foundational .NET runtime/QUIC transport flaw enabling unauthenticated memory disclosure of tokens and keys across public-facing APIs and cloud services. | A TIER 2 flaw in Microsoft’s .NET QUIC implementation exposes sensitive memory (tokens, API keys) to unauthenticated attackers. As a foundational transport layer for modern public APIs and cloud services, patching .NET runtimes is critical for any regulated or citizen-facing digital infrastructure. |
| 3 | 2 | CVE-2026-65791 | Foundational Windows Server storage flaw enabling unauthenticated RCE; underpins enterprise infrastructure critical to government, finance, and healthcare sectors. | CVE-2026-65791 delivers unauthenticated SYSTEM-level RCE in Windows iSCSI Target, creating a potent lateral-movement vector for internal storage networks. Regulated sectors relying on Windows Server SANs should enforce strict segmentation and patch promptly to protect critical data backends. |
| 3 | 2 | CVE-2026-72543 | Public-facing e-signature platform with unauthenticated PII leak; explicitly adopted by government, finance, and healthcare for contract management, posing compliance and data breach risks. | Unauthenticated IDOR in a widely deployed e-signature platform exposes contact PII by default. Critical for regulated sectors relying on digital contracts—patch immediately or restrict API access. |
| 2 | 2 | CVE-2026-62822 | TIER 2 Windows GDI+ RCE impacts foundational OS hosting regulated enterprise and public-sector services, requiring patching across government and financial infrastructure. | A TIER 2 Windows GDI+ vulnerability (CVE-2026-62822) enables RCE via crafted images, impacting the foundational OS layer for government, finance, and healthcare deployments. While delivery requires file processing, patching remains critical for all regulated environments hosting Windows workloads. |
| 2 | 2 | CVE-2026-72746 | General infrastructure remote desktop stack deployed in public sector/enterprise environments; authentication bypass impacts secure remote access operations. | FreeRDP’s RDSTLS handshake flaw (CVE-2026-72746) allows unauthenticated RDP session takeover when a specific security toggle is enabled. While disabled by default, public sector and enterprise remote access deployments should verify configurations and patch to 3.30.0 to protect critical remote infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-31936.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15554.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15561.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15562.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15567.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16053.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17061.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18129.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18635.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18690.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18696.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18697.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19516.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19546.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20745.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20747.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20878.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-34265.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44764.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47702.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48386.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48414.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48438.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48439.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48440.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50061.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50062.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50063.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50236.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50472.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54981.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54984.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58230.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58641.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59086.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59125.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59126.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59127.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59132.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-5917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59700.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61348.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61358.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61359.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61363.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61364.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61365.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61366.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61367.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61923.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61925.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61926.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61938.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62690.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62692.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62696.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62698.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62700.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62726.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62732.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62733.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62734.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62735.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62736.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62747.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62751.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62752.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62755.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62766.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62784.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62797.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62812.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62819.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62872.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62892.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62893.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62910.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63514.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63515.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63518.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63519.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63522.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63525.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63527.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63532.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63533.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64910.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64919.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64921.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65656.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65657.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65658.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65661.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65664.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65679.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65775.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65815.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66145.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66799.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68792.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68794.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68796.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68800.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68805.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68811.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68812.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68815.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69115.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70311.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70329.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70338.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70344.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70345.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70347.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71384.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71386.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71387.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72533.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72538.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72562.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72563.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72595.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72607.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72694.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72763.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72771.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72774.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73242.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-18125.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-20715.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-20795.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-65681.md` — heuristic TIER 3/4
