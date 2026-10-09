# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-09 16:39:46Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-08`
- **Included count:** 48

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-106126 | Critical command injection in Tenable Identity Exposure allows SYSTEM-level RCE on Domain Controllers, directly compromising enterprise digital identity and Active Directory monitoring infrastructure. | Tenable Identity Exposure faces a critical TIER 2 vulnerability enabling SYSTEM-level command execution on Domain Controllers via its SaaS management console. Organizations relying on this IdAM platform for Active Directory monitoring must patch immediately to prevent full domain compromise. |
| 5 | 2 | CVE-2026-107406 | Directly compromises SAML-based identity federation gateways, impacting enterprise and public-sector Digital Identity and access management infrastructure. | Unauthenticated RCE in Citrix NetScaler’s SAML processing could bypass critical identity gateways for government and enterprise SSO deployments. Patching or disabling unused SAML federation is essential to protect digital identity infrastructure. |
| 5 | 2 | CVE-2026-107720 | Core JWT authentication library bypass enables arbitrary identity/role forgery in public-facing APIs, directly impacting Digital Identity infrastructure. | A misconfigured JWT secret in a popular Node.js library can let attackers forge admin roles with unsigned tokens. Patch fast-jwt and validate secrets at startup to protect your digital identity stack. |
| 5 | 2 | CVE-2026-107722 | Critical JWT library flaw enabling authentication bypass and token forgery, directly impacting Digital Identity infrastructure and public-sector/enterprise identity gateways. | A critical vulnerability in the widely adopted fast-jwt Node.js library allows attackers to forge admin tokens via algorithm confusion, posing a direct threat to digital identity systems and citizen-facing APIs. Enforce strict algorithm allowlists and patch to v6.3.0+ to secure public-sector authentication pipelines. |
| 5 | 2 | CVE-2026-107723 | Digital Identity sector: bypasses JWT claim validation in widely deployed SSO/OIDC and federated identity systems critical to public and regulated services. | A silent JWT payload bypass in a widely used Node.js library could undermine trust in digital identity and SSO systems. Upgrade fast-jwt to v6.3.0 to protect authentication flows in regulated and public-sector services. |
| 5 | 2 | CVE-2026-107724 | Core JWT authentication library vulnerability enabling auth bypass in identity providers and public-facing APIs, directly impacting Digital Identity and regulated sector infrastructure. | A misconfigured JWT verifier can turn public keys into symmetric secrets, enabling full authentication bypass in widely used Node.js identity stacks. Patch fast-jwt and enforce asymmetric algorithm allowlists to protect digital identity gateways. |
| 5 | 2 | CVE-2026-15784 | Unauthenticated RCE in IBM DataPower Gateway, a foundational API/security gateway heavily deployed at the perimeter of Finance, Government, and Healthcare digital services. | IBM DataPower Gateway faces an unauthenticated RCE flaw (CVE-2026-15784) that could compromise perimeter security for critical API traffic. Organizations in finance, government, and healthcare should prioritize patching to protect citizen and payment-facing services. |
| 5 | 2 | CVE-2026-16164 | Unauthenticated remote DoS in IBM DataPower API gateways threatens availability of citizen-facing services, payment gateways, and health data exchanges across Finance, Government, and Healthcare sectors. | IBM DataPower gateways securing national APIs and payment systems face a new unauthenticated DoS risk. Patch edge infrastructure immediately to prevent disruption to critical public and financial services. |
| 5 | 2 | CVE-2026-16823 | Critical unauthenticated authentication bypass in IBM Security Verify Access directly compromises enterprise IdAM gateways and OAuth/OIDC identity providers foundational to digital public infrastructure. | A critical, unauthenticated bypass in IBM Security Verify Access could let attackers slip past enterprise identity gateways without credentials. For DPI ecosystems relying on OAuth/OIDC and SSO, this TIER 2 flaw demands immediate patching to protect citizen and enterprise access controls. |
| 5 | 2 | CVE-2026-16916 | Core IAM gateway vulnerability impacting authentication and session management for public-facing digital identity infrastructure. | IBM Security Verify Access RCE (CVE-2026-16916) underscores the critical need to secure edge IAM gateways. Though requiring high-privilege access, compromise could disrupt authentication flows and expose sensitive identity data across regulated sectors. |
| 5 | 2 | CVE-2026-18740 | Core enterprise IAM gateway flaw impacting authentication and authorization for Digital Identity and national public infrastructure. | IBM Security Verify Access IAM gateways face a high-severity argument injection vulnerability (CVE-2026-18740) that threatens authentication and session management for critical digital services. Immediate patching and MFA enforcement are vital to safeguard national identity and enterprise access infrastructure. |
| 5 | 2 | CVE-2026-19482 | Authenticated RCE in IBM Security Verify Access, a core Digital Identity IdAM gateway critical for secure citizen and enterprise access infrastructure. | A Tier 2 authenticated RCE in IBM Security Verify Access highlights the persistent risk to enterprise IdAM gateways. While credential barriers limit mass exploitation, compromised accounts could lead to full gateway control and credential harvesting—reinforcing the need for strict MFA and rapid patching in digital identity stacks. |
| 5 | 2 | CVE-2026-19491 | Critical unauthenticated authentication bypass in IBM Security Verify Access, a core enterprise IdAM gateway foundational to digital identity infrastructure. | A critical, unauthenticated auth bypass in IBM Security Verify Access exposes the perimeter gateways that protect enterprise and national digital identity services. Patching is urgent for any organization relying on this IdAM stack to secure citizen or customer access. |
| 5 | 2 | CVE-2026-19493 | Unauthenticated path traversal in IBM Security Verify Access IAM gateways enables arbitrary file writes, directly threatening digital identity infrastructure and perimeter authentication services in government and finance. | A critical unauthenticated path traversal in IBM Security Verify Access could let attackers write arbitrary files to enterprise IAM gateways, bypassing perimeter authentication and risking full system compromise. Organizations relying on this stack for digital identity and citizen/customer access should prioritize patching immediately. |
| 5 | 2 | CVE-2026-19494 | Core IdAM gateway authentication bypass impacting centralized identity providers and national digital infrastructure access controls. | A TIER 2 authentication bypass in IBM Security Verify Access highlights the critical need for strict credential hygiene and MFA enforcement in public-facing IAM gateways. For DPI operators, this underscores how even low-privilege credential compromise can cascade into full identity layer breaches. |
| 5 | 2 | CVE-2026-44031 | TIER 2 unauthenticated DoS in DCMTK, a foundational open-source library for DICOM medical imaging and hospital PACS systems, directly impacting healthcare availability. | Hospital PACS and radiology workflows face a critical availability risk: CVE-2026-44031 allows unauthenticated remote DoS in the widely deployed DCMTK DICOM library. Patching is essential to protect clinical imaging infrastructure. |
| 5 | 2 | CVE-2026-75875 | Critical unauthenticated RCE in IBM Guardium Sniffer, extensively deployed across Finance, Government, and Healthcare for regulatory compliance and database monitoring. | A critical path traversal flaw in IBM Guardium's internal Sniffer enables unauthenticated RCE with no available workarounds. Regulated sectors relying on this appliance for PCI-DSS and HIPAA compliance must patch immediately to block lateral movement and protect sensitive data streams. |
| 5 | 2 | CVE-2026-78401 | Unauthenticated RCE in IBM Security Verify Access/Identity Access, a core enterprise IdAM gateway securing government, healthcare, and financial digital services. | Critical unauthenticated RCE in IBM Security Verify Access exposes enterprise identity gateways to immediate takeover. Organizations relying on this IdAM stack for citizen or patient access must patch immediately to protect digital identity infrastructure. |
| 5 | 2 | CVE-2026-78406 | Critical unauthenticated RCE in enterprise IdAM gateways directly compromises authentication and session management infrastructure for the Digital Identity sector. | Unauthenticated RCE in IBM Security Verify Access (CVE-2026-78406) poses a critical risk to digital identity infrastructure, potentially allowing attackers to bypass authentication controls and hijack enterprise or public-sector access gateways. Prioritize patching and ensure IdAM components remain behind reverse proxies. |
| 5 | 2 | CVE-2026-80381 | Critical unauthenticated SQLi in IBM Guardium monitoring infrastructure directly impacts Finance, Government, and Healthcare compliance (PCI-DSS, HIPAA) by compromising audit logs and sensitive data protection. | A critical SQL injection in IBM Guardium’s internal monitoring layer could blind regulators and compliance teams across Finance, Healthcare, and Government. Patching this TIER 2 flaw is essential to preserve audit integrity and meet PCI-DSS/HIPAA mandates. |
| 4 | 2 | CVE-2026-104658 | Local privilege escalation in hMailServer impacts email gateways that underpin Digital Identity and General Infrastructure for government, finance, and healthcare communications. | Email gateways remain a critical attack surface for regulated sectors. This TIER 2 local privilege escalation in hMailServer highlights the need to patch mail infrastructure to protect government, finance, and healthcare communications from post-compromise root escalation. |
| 4 | 2 | CVE-2026-107333 | CISA-developed network monitoring platform for Government and Critical Infrastructure sectors; RBAC bypass enables privilege escalation in internal security operations environments. | A TIER 2 RBAC bypass in CISA’s Malcolm platform shows how internal security tools can become attack vectors when authorization logic isn't hardened. Government and critical infrastructure operators should patch immediately and enforce strict network segmentation. |
| 4 | 2 | CVE-2026-107779 | Unauthenticated RCE in an OA/ERP platform widely deployed in hospitals and public-sector institutions, risking patient/citizen data breaches and administrative service disruption. | Critical unauthenticated RCE in Dromara Skyeye’s job scheduler exposes internal OA/ERP systems used by hospitals and government agencies. Even behind firewalls, this trivial exploit path demands immediate network segmentation and access token enforcement to protect sensitive public and healthcare data. |
| 4 | 2 | CVE-2026-14269 | Critical unauthenticated RCE in IBM DataPower Gateway, a foundational API gateway explicitly deployed at the edge of Digital Identity, Finance, and Government services. | Unauthenticated RCE in IBM DataPower Gateway (CVE-2026-14269) poses a critical edge risk for regulated sectors. As a default internet-facing API gateway handling OAuth and secure routing for identity, finance, and government services, patching is urgent before exploitation scales. |
| 4 | 2 | CVE-2026-14888 | Unauthenticated RCE in IBM DataPower Gateway, a perimeter API/security middleware explicitly noted as widely deployed across Finance, Government, and Healthcare infrastructure. | Unauthenticated remote code execution in IBM DataPower Gateway exposes a critical perimeter risk for regulated sectors. Finance, government, and healthcare organizations relying on this API gateway should prioritize patching to prevent edge compromise and lateral movement. |
| 4 | 2 | CVE-2026-14905 | Unauthenticated XXE in IBM DataPower API gateways, foundational infrastructure explicitly deployed across Finance, Government, and Healthcare to secure critical public-facing API traffic. | IBM DataPower gateways securing Finance, Government, and Healthcare APIs face an unauthenticated XXE flaw that could expose sensitive data or disrupt services. Patching is critical for perimeter-facing infrastructure handling regulated digital services. |
| 4 | 2 | CVE-2026-14992 | Critical unauthenticated RCE in IBM DataPower Gateway, a foundational perimeter/API security appliance widely deployed to protect regulated and public-facing digital services. | A critical, unauthenticated RCE (CVSS 9.8) in IBM DataPower Gateway exposes a major attack surface for perimeter defenses. As a foundational API and security gateway, this Tier 2 flaw demands immediate patching to protect public-facing digital services and backend infrastructure. |
| 4 | 2 | CVE-2026-15762 | Critical unauthenticated RCE in IBM DataPower Gateway, a foundational API middleware widely deployed at the network edge for Finance, Government, and Healthcare digital services. | Unauthenticated RCE in IBM DataPower Gateway (CVE-2026-15762) threatens edge-facing API infrastructure supporting regulated sectors. Finance, government, and healthcare organizations relying on DataPower for secure API exposure should prioritize patching to prevent initial access and lateral movement. |
| 4 | 2 | CVE-2026-16159 | Unauthenticated remote DoS on IBM DataPower Gateway, a foundational edge API/security platform explicitly deployed across Finance, Government, and Healthcare to secure digital public services. | IBM DataPower Gateway, a critical edge security appliance for public and regulated services, faces an unauthenticated remote DoS vulnerability (CVE-2026-16159). Organizations in Finance, Government, and Healthcare should prioritize patching to prevent cascading API outages. |
| 4 | 2 | CVE-2026-16163 | Foundational API gateway infrastructure widely deployed at the network edge for public-sector and regulated enterprise services, with unauthenticated remote DoS risk. | IBM DataPower Gateway, a cornerstone of public-sector and enterprise API infrastructure, faces an unauthenticated remote out-of-bounds write (CVE-2026-16163). While no wild exploitation is confirmed, its default internet-facing deployment makes patching critical for protecting citizen-facing and regulated digital services. |
| 4 | 2 | CVE-2026-16167 | General infrastructure edge gateway vulnerability with explicit DPI relevance, risking availability for fronted identity, finance, and government service portals. | A remote, unauthenticated DoS in IBM DataPower Gateway can take down internet-facing API endpoints. DPI teams should prioritize patching these edge gateways to protect the availability of citizen-facing, identity, and payment services. |
| 4 | 2 | CVE-2026-16176 | Unauthenticated DoS in IBM DataPower Gateway, a foundational perimeter API gateway widely deployed in Finance and Government for open banking and citizen services. | A single unauthenticated request can take down IBM DataPower Gateways, the silent workhorses securing open banking APIs and government citizen portals. Patching is critical to prevent widespread public service outages. |
| 4 | 2 | CVE-2026-16181 | Unauthenticated authorization bypass in IBM DataPower Gateway, a foundational API edge proxy underpinning Finance, Government, and Healthcare digital services. | IBM DataPower Gateway faces a high-severity authorization bypass that could expose citizen, financial, and health data routed through public-facing API edges. Patching is critical for regulated sectors relying on this integration backbone. |
| 4 | 2 | CVE-2026-81932 | Unauthenticated SQLi in IBM Guardium compromises audit and compliance logging infrastructure critical to Finance, Healthcare, and Government regulated environments. | A silent SQL injection in IBM Guardium’s internal Sniffer component could blind compliance monitoring across banking, healthcare, and government networks. With zero workarounds and unauthenticated access, post-compromise attackers can erase audit trails and exfiltrate sensitive logs—making network segmentation and immediate patching critical for regulated sectors. |
| 4 | 2 | CVE-2026-82900 | TIER 2 path traversal in IBM Guardium threatens audit trails and data integrity for regulated Finance, Healthcare, and Government deployments relying on compliance monitoring. | Unauthenticated file deletion in IBM Guardium could cripple audit logs and compliance controls for banks, hospitals, and government agencies. Patching internal security appliances is critical to preserving regulatory integrity and preventing defense evasion. |
| 4 | 2 | CVE-2026-83943 | Foundational cloud API governance infrastructure explicitly tied to citizen-facing and government service portals, enabling secure digital public service delivery. | Azure API Center's high-severity info disclosure flaw highlights the need for strict RBAC and private endpoints in cloud API governance. For public sector and regulated enterprises, securing API metadata is critical to protecting citizen-facing digital services. |
| 4 | 2 | CVE-2026-84272 | Critical internal data protection/compliance infrastructure widely deployed in regulated Finance, Healthcare, and Government environments; unauthenticated RCE enables lateral movement and bypasses security controls. | IBM Guardium’s internal edge-controller has a critical missing-auth flaw (CVE-2026-84272) that allows unauthenticated RCE. While not internet-facing, it’s a high-value lateral movement target for attackers inside regulated Finance, Healthcare, and Government networks relying on it for PCI-DSS, HIPAA, and GDPR compliance. |
| 4 | 2 | CVE-2026-84275 | Unauthenticated path traversal in IBM Guardium compromises compliance monitoring infrastructure widely deployed in Finance, Healthcare, and Government for regulatory assurance. | Compromise of internal compliance appliances like IBM Guardium can silently undermine PCI-DSS and HIPAA audit trails. Regulated organizations must patch CVE-2026-84275 immediately to protect data sovereignty and regulatory assurance frameworks. |
| 4 | 2 | CVE-2026-93858 | TIER 2 OS command injection in OpenStack Mistral breaks multi-tenant isolation in sovereign/government cloud control planes, enabling lateral movement across public infrastructure. | Sovereign cloud operators and government IT teams should patch OpenStack Mistral immediately: a TIER 2 command injection flaw allows authenticated tenants to break multi-tenant isolation and compromise the control plane. Disabling the default std.ssh_proxied action is a quick mitigation while upgrades roll out. |
| 4 | 2 | CVE-2026-95184 | Foundational TLS/crypto library (GnuTLS) with network-triggered DoS risk, explicitly tied to national digital services and cross-sector DPI infrastructure. | A TIER 2 flaw in GnuTLS can silently break TLS handshakes for legitimate users, causing widespread DoS across national digital services. Patching this foundational crypto library is critical to keep public-facing infrastructure online. |
| 3 | 2 | CVE-2026-103649 | General infrastructure; mail servers are foundational for organizational continuity across all sectors. | A TIER 2 DoS in hMailServer Linux builds can halt outbound mail flow and auxiliary services via thread exhaustion, disrupting critical communications for organizations relying on this foundational infrastructure. |
| 3 | 2 | CVE-2026-107574 | Tier 2 unauthenticated DoS in hMailServer disrupts core email infrastructure, a foundational cross-sector utility critical for institutional and public communications. | Email gateways are the backbone of institutional communications. This Tier 2 unauthenticated DoS in hMailServer can halt mail processing for over an hour, underscoring the need to patch foundational infrastructure before it becomes a cross-sector disruption vector. |
| 3 | 2 | CVE-2026-107576 | Unauthenticated DoS in a widely deployed email gateway disrupts foundational communications for government and regulated public-sector organizations. | Email gateways are the backbone of public-sector communications, but a simple crafted header can now exhaust hMailServer threads and halt official correspondence. Patching to v6.3.6 is critical for government and enterprise mail infrastructure to maintain service availability. |
| 3 | 2 | CVE-2026-15824 | Unauthenticated DoS on IBM DataPower API gateways, foundational edge infrastructure explicitly supporting Finance, Government, and Healthcare digital service ecosystems. | IBM DataPower gateways often sit at the edge of regulated and public-sector API ecosystems. This unauthenticated DoS flaw underscores the operational risk to citizen and financial services when edge infrastructure lacks active-active clustering or upstream traffic filtering. |
| 3 | 2 | CVE-2026-77900 | Critical unauthenticated RCE in Azure App Service, a foundational cloud PaaS widely used to host public-facing government, finance, and healthcare web applications and APIs. | Unauthenticated remote code execution in Microsoft Azure App Service poses a critical risk to public-facing digital services. Organizations hosting citizen-facing or regulated workloads on this PaaS should immediately enforce network restrictions and authentication controls. |
| 3 | 2 | CVE-2026-82335 | Enterprise security monitoring appliance (IBM Guardium) widely deployed in regulated Finance and Healthcare environments; unauthenticated RCE compromises compliance audit trails and data protection controls. | Unauthenticated RCE in IBM Guardium’s internal sniffer (CVE-2026-82335) threatens compliance monitoring in regulated Finance and Healthcare networks. Patch immediately to protect audit trails and prevent lateral movement within critical data infrastructure. |
| 3 | 2 | CVE-2026-83947 | Foundational Azure cloud infrastructure flaw enabling event spoofing; disrupts automated workflows in regulated sectors relying on event-driven architectures. | Cloud infrastructure integrity is critical for DPI: A Tier 2 authorization flaw in Azure Event Grid allows low-privilege attackers to spoof events, potentially disrupting automated workflows in finance, healthcare, and government systems. Enforce least-privilege controls and validate event sources. |
| 3 | 2 | CVE-2026-84249 | Critical unauthenticated management flaw in IBM Guardium, a compliance auditing appliance widely deployed in Finance and Government sectors to enforce PCI-DSS/GDPR data protection mandates. | Compromise of database monitoring tools like IBM Guardium can blind regulated organizations to data breaches and tamper with compliance audit trails. With no vendor workarounds available, Finance and Government IT teams must prioritize patching and strict network segmentation to protect critical audit infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-102488.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103010.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104075.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106429.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106433.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107362.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107573.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107589.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107611.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107615.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14507.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14990.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14991.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15819.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16161.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17189.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19083.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-5047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66084.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71183.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79842.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82344.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82895.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84057.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84230.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84875.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85421.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85423.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85486.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85487.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87424.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87663.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87664.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87666.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87667.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87674.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87675.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87679.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87681.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87683.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87685.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89091.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94578.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94581.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94586.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97147.md` — heuristic TIER 3/4
