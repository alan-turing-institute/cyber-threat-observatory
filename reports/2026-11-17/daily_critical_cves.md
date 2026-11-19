# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-19 10:02:23Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-17`
- **Included count:** 62

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-114824 | Core Oracle OPSS IdAM framework vulnerability enabling unauthenticated full takeover, directly impacting digital identity, government, and financial sector middleware deployments. | Unauthenticated RCE in Oracle’s OPSS security framework (CVE-2026-114824) threatens the identity and access management backbone of government and financial middleware. With CVSS 10.0 and no public PoC yet, regulated sectors should prioritize the Nov 2026 CSPU and verify network segmentation for DMZ-facing endpoints. |
| 5 | 2 | CVE-2026-114850 | Critical unauthenticated takeover in Oracle APEX directly threatens government citizen portals and financial enterprise workflows. | Unauthenticated remote takeover in Oracle APEX (CVSS 9.8) puts government citizen services and financial workflows at immediate risk. Patch now and verify internet exposure before attackers automate exploitation. |
| 5 | 2 | CVE-2026-114958 | Unauthenticated HTTP flaw in Oracle Hyperion exposes financial planning and government budgeting data, impacting Finance and Government sectors. | Oracle Hyperion's unauthenticated vulnerability poses a direct risk to financial integrity and government budgeting systems. Ensure network segmentation and apply the November CSPU to protect sensitive fiscal data from lateral movement. |
| 5 | 2 | CVE-2026-115051 | High-impact unauthenticated takeover in Oracle Hyperion EPM, a core financial planning and regulatory reporting platform widely deployed by banks, treasuries, and government agencies for fiscal governance. | Oracle Hyperion EPM, a backbone for corporate and government financial planning, faces a high-severity unauthenticated takeover flaw. While typically internal-facing, misconfigurations or lateral movement could expose critical fiscal data—prompting urgent patching for finance and public sector IT teams. |
| 5 | 2 | CVE-2026-124646 | Unauthenticated API bypass in India's government-deployed e-Sushrut HMIS exposes sensitive patient records, impacting Healthcare and Government DPI sectors. | A Tier 2 vulnerability in India's national hospital management system allows unauthenticated access to patient records via API manipulation. Critical for healthcare DPI resilience and government data protection compliance. |
| 5 | 2 | CVE-2026-127369 | Critical unauthenticated flaw in Oracle Hyperion Financial Close Management enables direct manipulation of financial reconciliation data, impacting enterprise Finance operations and audit integrity. | Unauthenticated access to financial close data? CVE-2026-127369 in Oracle Hyperion allows attackers to bypass auth and corrupt reconciliation records. Finance teams: patch now and segment your EPM backends. |
| 5 | 2 | CVE-2026-128073 | Directly compromises SAML 2.0 authentication infrastructure, enabling unauthenticated DoS against federated identity and SSO gateways critical to government, finance, and healthcare digital services. | A ready-to-use PoC can crash SAML-based login portals with a single malformed request, threatening the availability of federated identity systems across government and enterprise sectors. Patch gosaml2 to v0.12.0 immediately to protect your SSO infrastructure. |
| 5 | 1 | CVE-2026-130583 | Critical unauthenticated SSRF in a widely deployed Magento payment extension enables active exploitation, credential theft, and card skimmer deployment targeting financial transaction infrastructure. | Active exploitation of a critical SSRF in a popular Magento payment extension is enabling rapid store compromises and card skimmer deployments. Finance and e-commerce operators must patch immediately to protect payment processing infrastructure and customer financial data. |
| 5 | 2 | CVE-2026-80322 | Race condition in PingAuthorize API gateway leaks cross-request data, impacting authentication/authorization flows critical to national digital identity infrastructure. | Unauthenticated race condition in PingAuthorize API gateways can leak sensitive tokens and session data across requests. Critical patch required for IdAM deployments securing national digital identity and public services. |
| 5 | 2 | CVE-2026-91498 | Unauthenticated SAML flaw in Oracle Access Manager directly compromises enterprise IAM/SSO infrastructure, impacting Digital Identity services. | Enterprise SSO gateways are internet-facing by design, making unauthenticated SAML flaws like CVE-2026-91498 a direct threat to digital identity infrastructure. Patching OAM is critical to prevent policy bypass and credential harvesting in regulated environments. |
| 5 | 2 | CVE-2026-91500 | Critical unauthenticated flaw in Oracle Access Manager, a core enterprise IAM gateway, directly impacting the Digital Identity sector and national identity layers. | A CVSS 10.0, unauthenticated vulnerability in Oracle Access Manager exposes a critical gap in enterprise identity gateways. For DPI operators, this underscores the urgent need to patch perimeter authentication engines before they become easy entry points for attackers. |
| 5 | 2 | CVE-2026-91507 | Core IdAM authentication engine vulnerability enabling unauthenticated remote compromise of session and policy data, directly impacting digital identity infrastructure for regulated sectors. | Unauthenticated access to Oracle Access Manager's authentication engine could let attackers hijack sessions or alter access policies across entire enterprise ecosystems. Prioritize patching your IdAM gateways to protect digital identity infrastructure. |
| 5 | 2 | CVE-2026-91509 | Core IdAM/SAML gateway vulnerability enabling unauthenticated data manipulation, directly impacting digital identity infrastructure for government, healthcare, and enterprise sectors. | Unauthenticated SAML flaws in enterprise identity gateways can bypass authentication perimeters and corrupt critical access controls. Patching Oracle Access Manager is critical for protecting digital identity infrastructure across regulated sectors. |
| 5 | 2 | CVE-2026-91510 | Critical unauthenticated flaw in Oracle Access Manager directly compromises enterprise identity gateways, SSO, and credential/session management, posing immediate risk to Digital Identity infrastructure. | Unauthenticated CVSS 10.0 flaw in Oracle Access Manager exposes internet-facing identity gateways to credential theft and session manipulation. Organizations relying on OAM for SSO and MFA should prioritize the Nov 2026 CSPU patch immediately. |
| 5 | 2 | CVE-2026-91516 | Unauthenticated DoS on Oracle Access Manager disrupts core enterprise and public-sector digital identity and SSO authentication flows. | A single unauthenticated TCP request can crash Oracle Access Manager, locking out users from critical SSO and enterprise portals. Prioritize patching and network-level rate limiting to protect your digital identity choke points. |
| 5 | 2 | CVE-2026-91522 | Core enterprise IdAM/SSO gateway vulnerability enabling unauthenticated SAML-based authentication bypass, directly impacting digital identity trust boundaries for government, finance, and healthcare services. | A single flaw in an enterprise SSO gateway can compromise the entire digital identity trust chain. CVE-2026-91522 highlights why securing SAML endpoints and IdP configurations is non-negotiable for public and regulated services. |
| 5 | 2 | CVE-2026-91531 | Core enterprise IdAM stack vulnerability impacting authentication and SSO services widely deployed across government, finance, and healthcare digital identity perimeters. | Unauthenticated access to Oracle Access Manager’s authentication engine poses a direct threat to digital identity perimeters. With OAM widely securing citizen, banking, and healthcare portals, this TIER 2 flaw demands immediate patching to prevent credential manipulation and service disruption. |
| 5 | 2 | CVE-2026-91533 | Core enterprise IdAM gateway vulnerability enabling unauthenticated access to critical identity data, directly impacting digital identity infrastructure across government, finance, and healthcare. | Unauthenticated remote access to Oracle Access Manager could compromise the foundational trust layer of digital identity systems. Organizations relying on OAM for citizen, patient, or customer authentication should prioritize patching to prevent credential harvesting and account takeover. |
| 5 | 2 | CVE-2026-91540 | Core IdAM vulnerability in Oracle Access Manager affecting SAML authentication and identity data integrity. | Oracle Access Manager flaw (CVE-2026-91540) threatens enterprise identity infrastructure via SAML manipulation. Patching is critical for organizations relying on OAM for authentication gateways. |
| 5 | 2 | CVE-2026-91543 | Directly impacts the Digital Identity sector by compromising Oracle Access Manager's unauthenticated authentication engine, a core IdAM gateway for enterprise and public-sector access control. | A critical unauthenticated flaw in Oracle Access Manager’s authentication engine exposes enterprise and public-sector identity gateways to remote compromise. Organizations relying on OAM for citizen or employee access should prioritize the November 2026 patch to prevent unauthorized credential and session manipulation. |
| 5 | 2 | CVE-2026-91671 | Core enterprise IdAM platform (Oracle Access Manager) vulnerability directly compromises authentication gateways, impacting national digital identity and SSO infrastructure. | A Tier 2 flaw in Oracle Access Manager's Authentication Engine could allow attackers to fully compromise enterprise identity gateways. For DPI operators, this underscores the critical need to patch core IdAM platforms protecting national digital identity and SSO services. |
| 4 | 2 | CVE-2026-110782 | Core SAML2 library flaw enabling cross-IdP authentication bypass, directly impacting federated digital identity and SSO trust chains. | A high-severity flaw in SimpleSAMLphp could let attackers bypass SSO authentication in federated environments. Even with niche configuration requirements, identity providers and public-sector SSO gateways should patch immediately to protect critical trust boundaries. |
| 4 | 2 | CVE-2026-114799 | Unauthenticated data exposure in Oracle Hyperion Planning directly impacts Finance and Government sectors by compromising sensitive budgeting, forecasting, and fiscal planning data. | Financial institutions and government agencies relying on Oracle Hyperion Planning should prioritize patching this unauthenticated data leak. Even behind firewalls, internal network access alone is enough to expose critical fiscal forecasts and budget data. |
| 4 | 2 | CVE-2026-114862 | Unauthenticated data compromise in Oracle PeopleSoft ERP/HR platform, widely deployed across government, healthcare, and financial institutions for core payroll and administrative operations. | Critical unauthenticated flaw in Oracle PeopleSoft exposes sensitive HR and financial data across public sector and regulated enterprise deployments. Patching and network segmentation are essential to protect core government and healthcare ERP infrastructure. |
| 4 | 2 | CVE-2026-114933 | Unauthenticated data access and modification in Oracle PeopleSoft ERP, a critical internal platform widely deployed across government agencies and financial institutions for core procurement, HR, and accounting operations. | Oracle PeopleSoft’s unauthenticated HTTP flaw (CVE-2026-114933) poses a high-value lateral-movement risk for government and finance sectors relying on the suite for core financial and HR operations. While typically internal-facing, perimeter breaches or misconfigurations could expose critical public-sector data, making immediate patching and strict network segmentation essential. |
| 4 | 2 | CVE-2026-114934 | Critical unauthenticated flaw in Oracle PeopleSoft Integration Broker, widely deployed across Government, Healthcare, and Finance ERPs for sensitive cross-system data flows. | Oracle PeopleSoft's Integration Broker faces a critical unauthenticated access flaw (CVE-2026-114934) that threatens internal data integrity across government, healthcare, and finance ERPs. While default deployment is internal, post-compromise lateral movement risks make immediate patching and network segmentation vital for DPI resilience. |
| 4 | 2 | CVE-2026-114938 | Foundational Java SE runtime flaw impacting enterprise backends across Finance, Healthcare, Government, and Identity sectors; requires patching or JVM flag workaround to secure public-facing services. | A high-severity heap overflow in Oracle Java SE’s Base64 decoder could compromise the foundational runtimes powering critical public and enterprise services. While exploitation requires specific CPU features and API usage, the broad deployment footprint makes immediate patching or JVM flag mitigation essential for regulated environments. |
| 4 | 2 | CVE-2026-115047 | Critical unauthenticated RCE in Oracle Hyperion EPM suite directly threatens financial reporting integrity and government budgeting systems. | An unauthenticated RCE in Oracle Hyperion creates a high-value lateral movement primitive for attackers inside financial and government networks. Prioritize patching to safeguard critical budgeting, compliance, and treasury infrastructure. |
| 4 | 2 | CVE-2026-115076 | TIER 2 vulnerability in Oracle Hyperion Financial Close Management directly impacts the Finance sector by enabling unauthorized access to critical reconciliation and reporting data. | Financial data integrity is under pressure: a new TIER 2 flaw in Oracle Hyperion Financial Close Management allows low-privileged attackers to breach critical reconciliation data. Enterprises and public sector finance teams should prioritize patching and enforce strict network segmentation. |
| 4 | 2 | CVE-2026-115078 | Directly impacts the Finance sector by compromising Oracle Hyperion Financial Management, a core system for government fiscal reporting, central bank operations, and institutional budget consolidation. | Unauthenticated access to Oracle Hyperion Financial Management poses a critical risk to public fiscal transparency and institutional budget integrity. Organizations relying on this EPM suite for regulatory reporting and sovereign financial management should prioritize patching and network segmentation immediately. |
| 4 | 2 | CVE-2026-115086 | Critical unauthenticated RCE in Oracle Hyperion Planning, a core enterprise financial planning suite, posing high lateral-movement risk to regulated finance environments. | Unauthenticated RCE in Oracle Hyperion Planning (CVSS 9.8) underscores the lateral-movement risks within enterprise finance stacks. Even when internal-only, critical financial planning tools demand strict network segmentation and rapid patching to safeguard strategic fiscal data. |
| 4 | 2 | CVE-2026-115166 | Core enterprise financial planning and regulatory reporting infrastructure (Oracle Hyperion) vulnerable to unauthenticated internal data access, impacting regulated finance sector operations. | Financial institutions and regulated enterprises relying on Oracle Hyperion for budgeting and reporting should prioritize patching this unauthenticated internal flaw. While not internet-facing, it offers attackers a high-value lateral movement path to sensitive financial data once inside the network. |
| 4 | 2 | CVE-2026-119293 | Foundational VoIP/telecom stack widely deployed across Healthcare, Government, and Finance for emergency services and contact centers; plaintext RTP hijack degrades critical communications infrastructure. | FreeSWITCH’s RTP source-learning flaw (CVE-2026-119293) enables remote audio eavesdropping and injection on plaintext VoIP calls. As a foundational telecom stack powering government emergency lines, healthcare communications, and financial contact centers, patching and enforcing SRTP is critical to protect regulated voice infrastructure. |
| 4 | 2 | CVE-2026-126966 | Enterprise email and identity management platform with missing authorization controls enabling domain admin privilege escalation, impacting organizational account security and access governance. | A TIER 2 flaw in SmarterMail shows how missing authorization checks in enterprise email platforms can turn compromised user accounts into full domain admin access. Organizations relying on webmail for staff and citizen communications should prioritize patching and enforce MFA to protect identity and access controls. |
| 4 | 2 | CVE-2026-127362 | Finance sector: unauthenticated data access and modification in Oracle Hyperion Financial Close Management threatens regulated accounting, reconciliation, and compliance workflows. | Unauthenticated access to critical financial reconciliation data in Oracle Hyperion highlights the need for strict internal segmentation and patching in regulated finance environments. Even internal-only enterprise apps require robust defense-in-depth to protect financial integrity and compliance. |
| 4 | 2 | CVE-2026-127370 | Unauthenticated remote access flaw in Oracle Hyperion Financial Close Management, directly impacting Finance sector reconciliation and reporting operations. | Financial institutions relying on Oracle Hyperion for close cycles should prioritize patching this unauthenticated flaw (CVE-2026-127370). While typically internal, its high CVSS and lack of auth requirements make it a critical risk for lateral movement and data integrity in regulated finance environments. |
| 4 | 2 | CVE-2026-129272 | Critical authentication bypass in widely deployed RMM infrastructure that can pivot to compromise endpoints across Digital Identity, Finance, and Government sectors. | Compromised RMM platforms are a high-value pivot point for attackers targeting regulated sectors. This TIER 2 flaw in N-able N-central enables unauthenticated appliance impersonation, threatening the endpoint security posture of MSPs managing government, financial, and identity infrastructure. |
| 4 | 2 | CVE-2026-28273 | Government, General Infrastructure: Authenticated RCE in ZoneMinder CCTV software impacts municipal surveillance and critical infrastructure monitoring, risking citizen privacy. | Municipal and government security teams should prioritize patching ZoneMinder (CVE-2026-28273). This authenticated RCE flaw in widely deployed CCTV management software poses direct risks to citizen privacy and critical infrastructure monitoring, with a ready-to-use PoC already circulating. |
| 4 | 2 | CVE-2026-61676 | Unauthenticated billing manipulation in a charitable institution ERP directly impacts financial integrity and healthcare service operations. | Charitable and healthcare institutions using WeGIA face critical financial data manipulation risks via an unauthenticated billing flaw. Patch to v3.8.7 immediately to protect donation integrity and operational trust. |
| 4 | 2 | CVE-2026-61680 | Unauthenticated financial record manipulation in a public-facing NGO management platform directly impacts billing integrity and charitable fund operations (Finance sector). | A critical missing authentication flaw in a widely used NGO management platform allows attackers to generate arbitrary billing records without credentials. For civil society and public-facing financial systems, this highlights the urgent need to secure transaction endpoints and enforce strict session validation. |
| 4 | 2 | CVE-2026-69188 | RCE in a web management platform for charitable/assistential institutions handling patient and financial data, directly impacting Healthcare and Government DPI sectors. | A ready-to-use PoC for a high-severity RCE in WeGIA highlights the risks of legacy PHP stream wrappers in institutional web platforms. For Healthcare and Government DPI operators managing charitable or assistential services, enforcing strict backup-role access and patching to v3.9.1 is critical to protect sensitive patient and financial data. |
| 4 | 2 | CVE-2026-91456 | Foundational enterprise middleware explicitly deployed across government, finance, and healthcare backends; unauthenticated remote takeover threatens critical digital service orchestration. | Oracle WebLogic’s critical unauthenticated SOAP flaw (CVE-2026-91456) demands immediate patching for regulated sectors. As foundational middleware underpinning government, finance, and healthcare backends, its compromise risks widespread service disruption and data exposure. |
| 4 | 2 | CVE-2026-91470 | Critical unauthenticated RCE in Oracle WebLogic Server, a foundational enterprise middleware explicitly underpinning Finance, Government, and Healthcare digital services. | Unauthenticated RCE in Oracle WebLogic (CVE-2026-91470) poses a critical lateral movement risk for regulated sectors. While T3/IIOP ports are internal by default, misconfigurations expose Finance, Government, and Healthcare backends to full server takeover—patch and segment now. |
| 4 | 2 | CVE-2026-91569 | Critical unauthenticated RCE in Oracle WebLogic, foundational middleware explicitly tied to Finance, Government, and Healthcare backend deployments. | Oracle WebLogic’s CVSS 10.0 unauthenticated RCE (CVE-2026-91569) threatens the backend infrastructure of regulated sectors. Finance, government, and healthcare operators should prioritize patching and network segmentation ahead of the November CSPU. |
| 3 | 2 | CVE-2026-114857 | Foundational Oracle API middleware explicitly noted as backend infrastructure for regulated finance and government portals. | A Tier 2 flaw in Oracle REST Data Services (ORDS) risks full service takeover for organizations using it as a public-facing API layer. Finance and government portals leveraging Oracle APEX should prioritize patching and harden endpoint access controls. |
| 3 | 2 | CVE-2026-114925 | Critical unauthenticated RCE in Oracle E-Business Suite, a foundational ERP explicitly tied to Finance and Government sector deployments for core operational and financial record-keeping. | Unauthenticated RCE in Oracle E-Business Suite (CVE-2026-114925) poses a severe lateral movement risk for Finance and Government ERP deployments. While typically internal-facing, zero-authentication barriers make network segmentation and prompt patching critical for protecting core public and financial operations. |
| 3 | 2 | CVE-2026-115035 | Enterprise CRM platform widely deployed in regulated finance, healthcare, and government sectors for customer and citizen relationship management, posing data breach and service disruption risks. | Oracle Siebel CRM faces a high-severity takeover vulnerability (CVE-2026-115035) that could expose sensitive customer and citizen data across finance, healthcare, and government deployments. While authentication is required, the CVSS 8.8 impact underscores the need for strict network segmentation and prompt patching in regulated environments. |
| 3 | 2 | CVE-2026-119192 | Foundational Node.js cryptographic library (TLS/PKI) impacting supply-chain integrity across regulated sectors, though constrained by non-default e=3 key configuration. | A TIER 2 crypto flaw in the widely adopted node-forge library could undermine TLS and PKI trust in digital services, but requires a rare e=3 key setup. Patching this supply-chain staple remains critical for infrastructure resilience. |
| 3 | 2 | CVE-2026-119623 | General web infrastructure (TYPO3 CMS) widely deployed in government portals and regulated sectors, enabling unauthenticated RCE via installer re-enablement. | Public-facing CMS platforms like TYPO3 power many government and enterprise portals. This TIER 2 flaw shows how a simple marker file can bypass installer locks and grant full RCE—reminding admins to audit backup restores and restrict backend file writes. |
| 3 | 2 | CVE-2026-125159 | Affects TYPO3 CMS, widely deployed on government and institutional public-facing portals, enabling unauthenticated local file read and credential exposure. | Public-facing government and enterprise portals running TYPO3 CMS face a high-severity file disclosure risk via crafted image uploads. Patching or restricting upload MIME types is critical to protect institutional configuration data and credentials. |
| 3 | 2 | CVE-2026-126967 | Enterprise webmail server with SYSTEM-level RCE, explicitly noted as widely deployed across government, finance, and healthcare environments. | A TIER 2 authenticated RCE in SmarterMail underscores the risk to foundational IT infrastructure in regulated sectors. While an authentication barrier exists, SYSTEM-level access on public-facing mail servers requires immediate patching and strict MFA enforcement. |
| 3 | 2 | CVE-2026-129274 | General infrastructure RMM platform supporting regulated sector endpoints; legacy API auth bypass enables cross-tenant task forgery and RCE chains. | RMM platforms like N-central form the operational backbone for MSPs and enterprises managing regulated endpoints. A missing authentication flaw in its legacy API could let attackers forge execution tasks across tenants, underscoring why disabling non-default APIs is critical for infrastructure supporting public and financial services. |
| 3 | 2 | CVE-2026-21598 | Unauthenticated path traversal in Atlassian Bamboo Data Center exposes CI/CD credentials and configs, posing a horizontal confidentiality risk to government, finance, healthcare, and identity software delivery pipelines. | CI/CD pipelines are the backbone of modern digital public infrastructure. This unauthenticated path traversal in Atlassian Bamboo could expose critical build credentials and internal configs across government and regulated sectors—patching and network segmentation are essential. |
| 3 | 2 | CVE-2026-61675 | Unauthenticated financial record corruption in a public-facing donation/payment management system, directly impacting transaction integrity and financial auditing. | Public-facing charity management systems are falling prey to unauthenticated payment manipulation. This critical flaw allows attackers to alter financial records without credentials, highlighting the urgent need for strict authorization controls in all transaction-handling web apps. |
| 3 | 2 | CVE-2026-61677 | Unauthenticated data manipulation in a civic-sector management system risks integrity of sensitive citizen/member records handled by publicly funded charitable institutions. | Charitable and civic organizations managing sensitive citizen data should prioritize patching WeGIA to 3.8.7. This unauthenticated flaw allows attackers to silently corrupt member records, undermining trust in public-facing social assistance platforms. |
| 3 | 2 | CVE-2026-91469 | Critical unauthenticated flaw in Oracle WebLogic Server, a foundational enterprise middleware widely deployed to host regulated and public-facing digital services. | Unauthenticated critical vulnerability in Oracle WebLogic Server demands immediate patching for enterprises hosting public-facing or regulated applications. Network segmentation and WAF rules are essential stopgaps until Oracle's next CPU is applied. |
| 3 | 2 | CVE-2026-91583 | Unauthenticated RCE in Oracle WebLogic middleware, explicitly deployed across Finance and Government enterprise stacks, posing critical risk to regulated backend services. | Critical unauthenticated RCE in Oracle WebLogic demands immediate patching for Finance and Government IT teams. As foundational middleware underpinning regulated digital services, this zero-barrier flaw requires urgent mitigation to prevent full server takeover. |
| 3 | 2 | CVE-2026-91585 | TIER 2 unauthenticated RCE in Oracle WebLogic, a foundational enterprise middleware widely deployed across regulated finance, government, and healthcare environments. | Critical unauthenticated RCE (CVSS 9.8) in Oracle WebLogic demands immediate patching. As a backbone for enterprise and public-sector applications, this TIER 2 flaw highlights the need for strict network segmentation and CSPU compliance across regulated infrastructure. |
| 2 | 2 | CVE-2026-114817 | General infrastructure analytics platform explicitly tied to Finance, Healthcare, and Government DPI deployments processing sensitive operational data. | Oracle BI EE faces a high-severity unauthenticated takeover flaw (CVE-2026-114817). While typically internal, its role in regulated Finance, Healthcare, and Government analytics pipelines makes immediate patching critical for protecting sensitive operational data. |
| 2 | 2 | CVE-2026-119622 | General infrastructure CMS explicitly noted for public-sector/institutional deployment; missing authorization enables chained RCE on exposed backends. | Public and institutional websites running TYPO3 CMS face a chained RCE risk from missing backend authorization. Ensure patches are applied to block low-privilege escalation and installer re-enablement. |
| 2 | 2 | CVE-2026-125162 | General infrastructure CMS widely deployed in public-sector and enterprise environments; DoS risk impacts citizen-facing web availability. | Public-sector and enterprise websites running TYPO3 CMS face a cache-flooding DoS risk (CVE-2026-125162). Verify legacy cache validation settings or patch now to maintain availability for citizen-facing services. |
| 2 | 2 | CVE-2026-130838 | General infrastructure CalDAV/CardDAV server with critical auth bypass, explicitly tied to enterprise and public-sector IT deployments. | Radicale's critical authorization bypass (CVE-2026-130838) allows unauthenticated attackers to inherit group calendar access via stale sessions. Public-sector and enterprise IT teams running self-hosted CalDAV should audit group rights configurations and patch to v3.8.3. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-100963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-100972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101657.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101663.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101838.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114783.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114785.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114788.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114809.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114813.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114814.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114815.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114819.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114822.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114835.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114846.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114865.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114871.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114872.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114884.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114887.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114894.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114909.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114911.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114913.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114915.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114918.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114927.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114928.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114939.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114942.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114955.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114978.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114980.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114981.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115046.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115048.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115049.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115050.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115053.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115057.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115058.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115061.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115062.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115063.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115064.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115065.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115066.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115067.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115070.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115071.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115072.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115074.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115080.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115081.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115092.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115101.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115128.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115129.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115131.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115133.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115138.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115139.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115140.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115143.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115150.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115155.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115158.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115159.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115170.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115173.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115177.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118496.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118497.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123050.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12487.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126547.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126548.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126553.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126558.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127308.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127327.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127329.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127335.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127349.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127351.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127357.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127373.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127402.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127415.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127416.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127427.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130386.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130588.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130840.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130853.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130857.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130875.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131844.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21590.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21591.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21593.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21594.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21596.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21599.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21600.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21601.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21602.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21603.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65963.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83362.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83365.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91556.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91561.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91564.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91566.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91586.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91618.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-127331.md` — heuristic TIER 3/4
