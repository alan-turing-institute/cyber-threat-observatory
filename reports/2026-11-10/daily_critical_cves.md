# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-13 14:44:41Z
- **Reports folder:** `/root/cyberobs-backfill-20261110/reports/2026-11-10`
- **Included count:** 61

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-109799 | Compromises JWT-based identity propagation and audit integrity in SAP BTP, directly impacting Digital Identity and multi-tenant isolation for regulated enterprise services. | A default JWT verification flaw in SAP's Cloud SDK allows attackers to spoof tenant and user identities, poisoning audit logs and bypassing multi-tenant controls. For DPI and regulated enterprises, this underscores the critical need to enforce cryptographic validation at the identity layer before trusting downstream routing and telemetry. |
| 5 | 2 | CVE-2026-112966 | Unauthenticated DoS targeting Windows SAM disrupts core authentication and domain controller operations, directly impacting Digital Identity and government/enterprise infrastructure availability. | A TIER 2 unauthenticated DoS in Windows SAM could paralyze domain controllers and authentication services across government and enterprise networks. Patching and network segmentation are critical to protect core digital identity infrastructure from resource exhaustion attacks. |
| 5 | 2 | CVE-2026-119958 | Foundational Windows LDAP/Active Directory flaw enabling unauthenticated RCE, directly impacting Digital Identity, Government, Finance, and Healthcare sectors reliant on AD for core IdAM and access control. | Unauthenticated RCE in Windows LDAP/Active Directory (CVE-2026-119958) poses a critical lateral movement risk for national digital infrastructure. With AD underpinning identity and access across government, finance, and healthcare, immediate patching and network segmentation are essential to protect core IdAM services. |
| 5 | 2 | CVE-2026-120017 | Critical SAML2 authentication bypass in SAP NetWeaver enables unauthenticated identity impersonation, directly impacting Digital Identity and enterprise SSO deployments across government and finance. | A CVSS 10.0 SAML2 signature bypass in SAP NetWeaver lets attackers forge SSO tokens and impersonate privileged users without credentials. With no workaround available, organizations relying on SAP for digital identity and enterprise access must prioritize the November patch cycle. |
| 5 | 2 | CVE-2026-121668 | Azure Confidential Clean Rooms vulnerability impacts secure multiparty data collaboration critical for Finance, Healthcare, and Government analytics and compliance. | Data integrity in the cloud: A TIER 2 flaw in Azure Confidential Clean Rooms highlights risks for regulated sectors relying on secure multiparty analytics. Finance, Healthcare, and Government teams must verify authorization controls to protect sensitive collaborative datasets. |
| 5 | 2 | CVE-2026-121683 | Directly compromises certificate trust and authentication infrastructure for enterprise endpoint management, heavily impacting Digital Identity and Government sector deployments. | Unauthenticated certificate manipulation in Ivanti CSA (CVE-2026-121683) threatens the trust chain for enterprise and government endpoint management. Patch promptly to prevent MITM attacks and authentication bypasses in your digital identity infrastructure. |
| 5 | 2 | CVE-2026-123041 | TIER 2 cache-key flaw in Kong Gateway enables cross-caller data leakage, directly impacting Digital Identity (OAuth/SSO), Finance, Healthcare, and Government API deployments. | API gateways are the backbone of modern digital public infrastructure, but a flawed cache key in Kong Gateway could leak sensitive tokens and citizen data across users. Patching and config audits are critical for IAM and regulated API environments. |
| 5 | 2 | CVE-2026-125298 | Critical JWT auth bypass in telecom BSS impacting subscriber billing, payment processing, and state-linked carrier infrastructure (Finance/Government/Digital Identity). | Telecom operators relying on AsiaInfo BSS face critical authentication bypass risks enabling billing tampering and subscriber identity takeover. Patching and strict network segmentation are essential to protect critical national infrastructure and financial services. |
| 5 | 2 | CVE-2026-76964 | Unauthenticated RCE in SAP NetWeaver ICM/Web Dispatcher directly threatens Finance and Government ERP deployments, exposing regulated data and compliance frameworks. | SAP’s foundational ERP runtime faces a critical, unauthenticated RCE flaw (CVE-2026-76964) that bypasses default security controls. Finance and government sectors relying on SAP NetWeaver must prioritize patching to protect regulated data and maintain service continuity. |
| 5 | 2 | CVE-2026-85844 | Critical Kerberos authentication bypass impacting Windows Active Directory, directly affecting Digital Identity infrastructure across government, finance, and healthcare sectors. | A critical, unauthenticated Kerberos bypass (CVE-2026-85844) threatens the backbone of enterprise identity management. For DPI and regulated sectors relying on Active Directory, this TIER 2 flaw demands immediate patching and network segmentation to prevent full domain takeover. |
| 5 | 2 | CVE-2026-89126 | Core SAP ERP infrastructure vulnerability impacting Finance, Government, and Healthcare sectors with unauthenticated RCE risking citizen and financial data exfiltration. | Unauthenticated RCE in SAP Web Dispatcher (CVE-2026-89126) poses a critical risk to national ERP systems. Finance, government, and healthcare sectors relying on SAP must prioritize patching to protect sensitive citizen and financial data from perimeter breaches. |
| 5 | 2 | CVE-2026-96067 | Critical unauthenticated RCE in Windows Color Management impacts foundational infrastructure across Government, Finance, Healthcare, and Digital Identity sectors. | Unauthenticated remote code execution in Windows Color Management poses systemic risk to national digital infrastructure. Patch immediately to protect government, financial, and healthcare workloads relying on Microsoft OS foundations. |
| 5 | 2 | CVE-2026-96092 | Unauthenticated RCE in Windows DNS Server threatens foundational naming infrastructure, cascading across government, finance, healthcare, and identity services. | DNS is the silent backbone of digital public infrastructure. This TIER 2 Windows Server flaw enables unauthenticated RCE on critical resolvers, risking widespread service disruption across government, finance, and healthcare networks. Patch and segment now. |
| 4 | 2 | CVE-2026-107356 | Impacts U.S. Geological Survey (federal government) research portal, risking sensitive public-sector data via authenticated RCE. | Federal research portals face high-stakes risks: CVE-2026-107356 allows authenticated RCE on the USGS ARMI web app, highlighting the need for strict file upload controls in government digital infrastructure. |
| 4 | 2 | CVE-2026-109800 | Foundational SAP reverse proxy middleware heavily deployed in Finance, Government, and Healthcare ERP environments, where a single authenticated DoS can disrupt critical public and regulated enterprise services. | SAP Web Dispatcher serves as the internet-facing gateway for many regulated Finance, Government, and Healthcare ERP systems. This TIER 2 authenticated DoS vulnerability highlights the operational risk of unpatched reverse proxies in critical digital infrastructure. |
| 4 | 2 | CVE-2026-109803 | Critical code execution in SAP NetWeaver, a foundational enterprise platform explicitly deployed across government, finance, and healthcare digital services. | SAP NetWeaver remains a backbone for regulated sectors, making this authenticated code injection a priority patch for finance, government, and healthcare IT teams. Apply Security Note 3809153 and restrict XML Forms access immediately. |
| 4 | 2 | CVE-2026-111289 | Foundational enterprise productivity vulnerability with broad impact across Government, Finance, Healthcare, and Digital Identity workflows due to ubiquitous Microsoft Office deployment. | CVE-2026-111289 underscores how endpoint productivity suites remain a critical attack surface for regulated sectors. While requiring user interaction, its pervasive use in government, finance, and healthcare mandates strict patching and email filtering to protect digital public infrastructure. |
| 4 | 2 | CVE-2026-116945 | Unauthenticated RCE in Microsoft SQL Server poses systemic risk to Finance, Healthcare, and Government workloads relying on this foundational database for core data and transactional services. | A critical, unauthenticated RCE in Microsoft SQL Server (CVE-2026-116945) highlights the systemic risk to regulated sectors. Even with internal default deployment, misconfigured instances in Finance, Healthcare, and Government environments face severe lateral movement and data exfiltration threats—patching and network segmentation are non-negotiable. |
| 4 | 2 | CVE-2026-118149 | Foundational enterprise email infrastructure deployed across government, healthcare, and finance sectors, handling sensitive operational communications and citizen/patient data. | Microsoft Exchange Server faces a high-severity authenticated RCE (CVE-2026-118149) impacting government, healthcare, and financial networks. While exploitation requires valid credentials, the broad deployment in critical sectors makes patching and credential hygiene essential for DPI resilience. |
| 4 | 2 | CVE-2026-118150 | Authenticated privilege escalation in Microsoft Exchange Server impacts Government, Finance, and Healthcare sectors by compromising foundational email, identity federation, and compliance workflows. | CVE-2026-118150 introduces a TIER 2 privilege escalation in Microsoft Exchange Server that allows low-privilege users to bypass authorization controls. As Exchange underpins secure communications across government, finance, and healthcare, deploying the November patch and enforcing MFA is essential for regulated infrastructure. |
| 4 | 2 | CVE-2026-118208 | TIER 2 authenticated spoofing flaw in Microsoft Exchange Server impacts Government, Digital Identity, Finance, and Healthcare sectors by undermining email-based trust and identity assertions in regulated environments. | Microsoft Exchange Server faces a TIER 2 spoofing vulnerability that could undermine identity trust and secure communications across government and regulated sectors. While it requires authentication, patching and strict access controls remain critical for protecting public and enterprise email infrastructure. |
| 4 | 2 | CVE-2026-118741 | Foundational authentication flaw in ASP.NET Core Identity scaffolding enables password reset token hijacking, directly impacting digital identity systems across government, finance, and healthcare deployments. | A high-severity logic flaw in ASP.NET Core Identity templates could let attackers hijack password reset tokens and take over accounts. Since this framework underpins many public and regulated web services, developers must manually patch token delivery logic to prevent widespread identity compromise. |
| 4 | 2 | CVE-2026-120013 | Breaks multi-tenant OAuth credential isolation in SAP Cloud SDK, directly impacting Digital Identity and access management infrastructure. | A path traversal flaw in SAP’s Python Cloud SDK lets attackers bypass tenant isolation and steal OAuth secrets. For DPI and enterprise identity platforms, this underscores the critical need for strict input validation and allowlisting in backend IdAM integrations. |
| 4 | 2 | CVE-2026-121290 | Foundational enterprise routing platform (Arista EOS) underpins Finance, Government, and Healthcare networks; misconfigured BGP ports bypass control-plane protections, risking routing instability across critical public and regulated infrastructure. | Critical networking infrastructure like Arista EOS forms the backbone of Finance, Government, and Healthcare systems. A misconfigured BGP port can silently bypass security controls, risking routing instability—reminding operators that even niche configurations demand strict ACL hygiene in regulated environments. |
| 4 | 2 | CVE-2026-121680 | Impacts core Windows NTLM authentication, directly affecting credential integrity and access control in enterprise and government domain environments (Digital Identity sector). | NTLM remains a backbone for many enterprise and government networks. This TIER 2 flaw highlights why accelerating the shift to Kerberos/modern auth and enforcing SMB signing is critical for protecting digital identity infrastructure. |
| 4 | 2 | CVE-2026-124036 | Authorization bypass in FlockOS enables cross-tenant alert manipulation, directly impacting government public safety agencies and emergency response operations. | A TIER 2 authorization bypass in FlockOS allowed cross-tenant manipulation of alerts, posing a direct risk to government public safety operations. The vendor patched the SaaS platform server-side, highlighting the critical need for strict tenant isolation in civic emergency response tools. |
| 4 | 2 | CVE-2026-125336 | Undermines X.509 PKI trust models and TLS validation in node-forge, directly impacting Digital Identity and General Infrastructure across regulated sectors. | A bypass in node-forge’s certificate validation could allow attackers to spoof trusted hosts and intercept sessions. For DPI architects, this highlights the critical need to harden PKI trust chains and enforce strict nameConstraints in government and financial identity systems. |
| 4 | 2 | CVE-2026-125756 | General infrastructure email parser flaw bypasses SPF/DKIM/DMARC, directly impacting Digital Identity and Government communications security. | A parser differential in a widely used Node.js email library allows attackers to spoof sender addresses and bypass SPF/DKIM/DMARC checks. This undermines email authentication foundations critical to Digital Identity and Government communications, highlighting the need for robust header validation in public-facing mail gateways. |
| 4 | 2 | CVE-2026-125757 | Multi-tenant email platforms underpin Government, Finance, and Healthcare communications; compromise enables cross-tenant surveillance and service disruption across regulated sectors. | Email remains the backbone of digital public infrastructure. This TIER 2 SSTI in mailcow shows how a compromised admin credential can cascade into cross-tenant surveillance and platform-wide outages across regulated sectors, making strict access controls and rapid patching essential for DPI resilience. |
| 4 | 2 | CVE-2026-89103 | Critical pre-auth RCE in SAP Gateway middleware, foundational to Finance, Healthcare, and Government deployments handling regulated data and public services. | A CVSS 10.0 pre-auth RCE in SAP Gateway (PROXYGATE) threatens the core middleware underpinning Finance, Healthcare, and Government operations. Regulated organizations must prioritize patching and network segmentation to protect critical public and enterprise data. |
| 4 | 2 | CVE-2026-92439 | Authentication bypass in Kong Gateway's SAML plugin undermines cross-SP trust boundaries, directly impacting Digital Identity and public-sector SSO deployments. | A missing AudienceRestriction check in Kong Gateway’s SAML plugin could let attackers replay valid assertions from other services to bypass authentication. Critical for any organization relying on SAML-based SSO for government or enterprise APIs. |
| 4 | 2 | CVE-2026-92441 | General infrastructure edge API gateway with unauthenticated request smuggling risk, explicitly noted as widely deployed across finance, healthcare, and government sectors for routing sensitive internal APIs. | Kong Gateway's unauthenticated CRLF injection flaw enables HTTP request smuggling at the network edge, posing a direct bypass risk for upstream security controls in finance, healthcare, and government API deployments. Patching is critical for regulated edge infrastructure. |
| 4 | 2 | CVE-2026-92443 | Critical unauthenticated cache leakage in widely deployed edge API gateways, directly impacting public-facing Digital Identity, Finance, Healthcare, and Government services. | API gateways sit at the edge of every digital public service. CVE-2026-92443 allows unauthenticated attackers to bypass access controls and retrieve cached, sensitive responses across Kong Gateway deployments. Patching is critical for any organization managing citizen, patient, or financial data at the network perimeter. |
| 4 | 2 | CVE-2026-92545 | Foundational API gateway infrastructure explicitly tied to Finance, Government, and Healthcare deployments; cache isolation failure risks cross-tenant data leakage in regulated public-facing services. | API gateways are the backbone of modern digital public services, but a cache configuration flaw in Kong Gateway could leak sensitive data across hostnames. Organizations in finance, government, and healthcare should verify plugin settings and patch immediately to maintain strict multi-tenant isolation. |
| 4 | 2 | CVE-2026-96002 | Foundational Windows DNS Server RCE vulnerability that threatens the availability and integrity of all dependent digital public infrastructure services. | CVE-2026-96002 highlights why foundational infrastructure like DNS demands rigorous patching and segmentation. Even with a low-privilege auth requirement, a compromised Windows DNS server can cascade into widespread service disruption across government, finance, and healthcare ecosystems. |
| 4 | 2 | CVE-2026-96078 | Critical unauthenticated RCE in foundational Windows OS infrastructure explicitly tied to government and enterprise IT deployments, impacting internal server estates and workstations. | As Windows remains the backbone of government and enterprise IT, this critical RCE in Color Management highlights why disciplined patch cycles and internal network segmentation are essential for protecting public sector infrastructure. |
| 3 | 2 | CVE-2026-105578 | Foundational Windows/JScript RCE impacting all DPI sectors via general infrastructure deployment. | CVE-2026-105578 underscores the risk in foundational DPI infrastructure: a JScript RCE in Windows impacting government, finance, and healthcare environments. Though user interaction is required, the universal reliance on Windows mandates immediate patching across regulated sectors. |
| 3 | 2 | CVE-2026-107241 | General infrastructure (SD-WAN edge devices) widely deployed in government, finance, and healthcare networks; default credential exposure in provisioning services poses configuration risk to regulated edge infrastructure. | SD-WAN edge devices form the backbone of modern government and enterprise networks. This TIER 2 vulnerability highlights how overlooked provisioning services with default credentials can expose critical infrastructure—reminding operators to disable temporary setup interfaces post-deployment. |
| 3 | 2 | CVE-2026-107246 | General infrastructure flaw in a widely deployed web hosting control panel that explicitly impacts public-sector and regulated web services via multi-tenant root compromise. | A critical path traversal in Plesk's Site Import extension (CVE-2026-107246) can escalate compromised subscription accounts to full root access. Public-sector and enterprise hosting providers should patch immediately to secure multi-tenant web infrastructure. |
| 3 | 2 | CVE-2026-114149 | Foundational web framework (ASP.NET Core) underpinning public-facing government and enterprise APIs, vulnerable to unauthenticated DoS. | A Tier 2 DoS flaw in Microsoft ASP.NET Core bypasses header limits, threatening the availability of public-facing government and enterprise APIs. Patching .NET runtimes is critical to maintain service continuity. |
| 3 | 2 | CVE-2026-116928 | Foundational Windows/Exchange infrastructure widely deployed in government and finance sectors, enabling zero-click RCE via email indexing. | Zero-click RCE in Windows Search via Exchange Server indexing poses a silent threat to government and financial infrastructure. Patching is critical for organizations relying on on-premises mail systems. |
| 3 | 2 | CVE-2026-118715 | General enterprise infrastructure vulnerability with widespread deployment across government and commercial sectors, requiring patching to protect endpoints handling sensitive public and corporate data. | Microsoft Excel heap overflow (CVE-2026-118715) rated TIER 2 highlights the persistent risk of user-triggered privilege escalation in foundational enterprise tools. Organizations should prioritize patching and enforce Attack Surface Reduction rules to secure government and commercial endpoints. |
| 3 | 2 | CVE-2026-118737 | Foundational Windows RPC RCE impacting core server stacks that underpin regulated and public digital services. | A Tier 2 Windows RPC flaw enables unauthenticated remote code execution across enterprise networks, highlighting the need for strict segmentation and rapid patching in critical infrastructure environments. |
| 3 | 2 | CVE-2026-119446 | Compromises authentication and API token issuance in an internet-facing fleet management platform, directly impacting Digital Identity and access control infrastructure. | A TIER 2 session fixation flaw in NervesHub’s CLI login flow allows attackers to steal API tokens via phishing, highlighting the critical need to harden authentication and token management in internet-facing IoT and fleet management platforms. |
| 3 | 2 | CVE-2026-119962 | TIER 2 unauthenticated RCE in Windows CredSSP impacts foundational authentication infrastructure widely deployed across government and regulated enterprise environments. | CVE-2026-119962 exposes a high-severity, unauthenticated RCE in Windows CredSSP. Though wild exploitation isn't confirmed, the vulnerability underscores the need for strict RDP/WinRM segmentation and rapid patching across public-sector and regulated IT environments. |
| 3 | 2 | CVE-2026-120000 | High-severity RCE in Microsoft SharePoint Server, a foundational collaboration platform explicitly deployed across Government, Healthcare, and Finance sectors for sensitive document management. | SharePoint remains a critical backbone for public and regulated sector collaboration. This TIER 2 deserialization flaw highlights the persistent risk of post-compromise escalation in enterprise environments—prompting immediate patching and strict access controls for government and healthcare deployments. |
| 3 | 2 | CVE-2026-120982 | Foundational enterprise networking OS underpins Finance, Government, and Healthcare infrastructure; BGP disruption risks widespread service availability. | Network stability is the backbone of digital public services. This TIER 2 BGP vulnerability in Arista EOS highlights why routing hardening and peer authentication remain critical for protecting finance, government, and healthcare infrastructure from availability attacks. |
| 3 | 2 | CVE-2026-121653 | Critical unauthenticated RCE in enterprise endpoint management infrastructure that underpins IT operations across public and private sector deployments. | Unauthenticated RCE in Ivanti Endpoint Manager highlights the risk to foundational IT management layers. Even when deployed internally, compromised endpoint controllers can cascade across entire public and enterprise networks—patching and strict segmentation are essential. |
| 3 | 2 | CVE-2026-124037 | Government sector relevance due to municipal/law enforcement deployment of the Flock Safety platform, exposing resident PII through a public-facing community alert feature. | Municipal governments and law enforcement agencies relying on cloud-hosted public safety platforms must monitor vendor-managed patches closely. CVE-2026-124037 exposed resident PII through a community sign-up feature, highlighting how public-facing interfaces in government-contracted infrastructure require strict access controls. |
| 3 | 2 | CVE-2026-125297 | Critical telecom BSS backend flaw enabling unauthenticated admin takeover and subscriber data manipulation, impacting national communications infrastructure. | Telecom operators must urgently patch AsiaInfo BSS management APIs. The missing authentication allows remote attackers to provision admin accounts, reset passwords, and manipulate subscriber records, posing a severe risk to national communications infrastructure. |
| 3 | 2 | CVE-2026-126186 | General infrastructure flaw in Ruby on Rails Active Storage impacting public-facing web apps across government and commercial sectors. | Public-facing Ruby on Rails applications face RCE risks via Active Storage file extension confusion. Patching is essential for government and enterprise services to prevent credential exposure and remote code execution. |
| 3 | 2 | CVE-2026-12708 | Foundational HTTP/3/QUIC transport library vulnerability enabling remote DoS on public-facing web services and cloud edge infrastructure. | A TIER 2 remote DoS in Cloudflare’s tokio-quiche library underscores the operational risk of default-enabled HTTP/3 DATAGRAM support. Public-facing web services and cloud providers must disable DATAGRAMs or patch immediately to prevent unbounded memory exhaustion on critical internet transport layers. |
| 3 | 2 | CVE-2026-57890 | TIER 2 hypervisor vulnerability in Intel TDX confidential computing infrastructure (General Infrastructure), impacting foundational cloud/enterprise environments that underpin regulated digital services. | Intel TDX hypervisor flaw (CVE-2026-57890) exposes sensitive migration data at Ring 0. While internal-facing, it underscores the need for strict network segmentation in confidential computing deployments supporting regulated services. |
| 3 | 2 | CVE-2026-81384 | Foundational Windows DNS Server RCE impacts enterprise and public-sector network routing, though limited by a non-default plugin requirement. | Unauthenticated RCE in Windows DNS Server (CVE-2026-81384) poses a Tier 2 risk to enterprise and public-sector networks. While a niche configuration barrier limits mass exploitation, organizations relying on Windows DNS for critical infrastructure should audit plugins and apply patches immediately. |
| 3 | 2 | CVE-2026-92684 | General infrastructure GraphQL library with authentication bypass impacting APIs deployed in Finance, Healthcare, and Government sectors for sensitive data access. | A TIER 2 auth bypass in the @neo4j/graphql library lets attackers skip field-level protections via aggregation queries. Critical for regulated sectors relying on graph APIs for fraud detection, clinical networks, and civic data mapping. |
| 3 | 2 | CVE-2026-95956 | General infrastructure vulnerability affecting Windows OS/server environments widely deployed in government and enterprise networks, enabling unauthenticated lateral movement. | Unauthenticated RCE in Windows eSCL Scanner poses a lateral movement risk for internal enterprise and government networks. Patching and disabling unused scanner services are critical for maintaining secure internal perimeters. |
| 3 | 2 | CVE-2026-95962 | TIER 2 unauthenticated RCE in Windows Server's core networking stack, foundational to regulated enterprise and public-sector infrastructure. | A critical Windows kernel vulnerability enables unauthenticated remote code execution across all supported Server versions. With no configuration workaround available, immediate patching is essential for any organization relying on Windows for regulated or public-facing digital services. |
| 2 | 2 | CVE-2026-113814 | Affects Windows Server 2025 and Windows 11, foundational OS layers explicitly noted as critical to government and enterprise IT stacks. | Windows Server 2025 and Windows 11 face a TIER 2 RCE in the Storage Spaces Controller. While user interaction is required and no wild exploitation is seen, patching remains critical for government and enterprise infrastructure relying on Microsoft's core OS stack. |
| 2 | 2 | CVE-2026-121289 | Foundational enterprise networking OS (Arista EOS) underpins public and regulated digital services; BGP agent RCE/DoS threatens core routing stability across government, finance, and healthcare infrastructure. | Core network infrastructure is the backbone of digital public services. This TIER 2 BGP vulnerability in Arista EOS highlights the need for strict peering controls and TCP-AO authentication to protect routing stability across regulated environments. |
| 2 | 2 | CVE-2026-88236 | General infrastructure risk: unauthenticated QUIC DoS on Windows Server disrupts public-facing enterprise and public-sector digital services. | A Tier 2 QUIC protocol flaw in Windows Server enables unauthenticated remote DoS, threatening the availability of HTTP/3-dependent public and enterprise services. Rapid patching or edge-level QUIC filtering is essential to maintain uptime for critical digital infrastructure. |
| 2 | 2 | CVE-2026-97891 | TIER 2 unauthenticated DoS in Eclipse Kura IoT gateway framework, foundational edge infrastructure for municipal and industrial digital services. | CVE-2026-97891 allows unauthenticated DoS of Eclipse Kura IoT gateways, disrupting municipal and industrial edge workloads. Restrict admin console access via firewall and patch to 5.6.3 to maintain infrastructure availability. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-61625.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102230.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105512.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105518.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105520.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105534.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105558.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105560.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105561.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105579.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105986.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108186.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108401.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108421.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109457.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109472.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109475.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109487.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109491.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109496.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109497.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109499.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109500.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109501.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109502.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109503.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109504.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109794.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109795.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109797.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110045.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110050.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110053.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110055.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110060.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110061.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110062.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110065.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110067.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111285.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111296.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111308.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112136.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112186.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112191.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112726.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112727.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112728.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112733.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112734.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112735.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112737.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112762.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113580.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113823.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114162.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114171.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114359.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115538.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116698.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116923.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116925.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116926.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116931.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116936.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116938.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116943.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118109.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118112.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118115.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118148.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118293.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118296.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118301.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118702.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118703.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118705.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118706.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118707.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118712.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118716.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118718.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118726.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118730.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118731.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118732.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118735.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118745.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118747.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119858.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119938.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119945.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119967.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119969.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119983.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119986.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119988.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119995.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120001.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120010.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120012.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120015.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120792.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120804.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120807.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120808.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120813.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120818.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120828.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121291.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121350.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121368.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121370.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121529.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121663.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121664.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121665.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121890.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122171.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122194.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122198.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122475.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12266.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-122988.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123377.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123379.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123380.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123384.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123387.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123390.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123391.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123717.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124227.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124228.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124747.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125329.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125331.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12573.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-125882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126123.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-26248.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50109.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59986.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60038.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60039.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60040.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60041.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63011.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66813.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67387.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67391.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67632.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72998.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76965.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76966.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84010.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85838.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85923.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88222.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91755.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94511.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95964.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95996.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96010.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96020.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96993.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97401.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-105515.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-125327.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-70240.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-76970.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-76973.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-95651.md` — heuristic TIER 3/4
