# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-23 15:20:53Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-22`
- **Included count:** 36

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-105270 | Directly compromises SAML-based SSO infrastructure (Digital Identity sector), enabling unauthenticated DoS against public-facing identity federation endpoints used by government, healthcare, and finance. | A single crafted SAML response can crash entire Erlang-based identity nodes, exposing a critical DoS risk for SSO infrastructure. Organizations relying on SAML federation should patch immediately to protect public-facing authentication endpoints. |
| 5 | 2 | CVE-2026-111594 | Core healthcare interoperability platform transmits patient data and credentials in cleartext by default, directly impacting hospital and public health system infrastructure. | Hospitals and health systems running InterSystems IRIS should verify TLS settings immediately—this TIER 2 flaw leaves patient records and admin credentials exposed in cleartext on internal networks. A quick config change blocks sniffing attacks and keeps clinical data secure. |
| 5 | 2 | CVE-2026-113873 | Unauthenticated DoS in HAPI FHIR, a core healthcare interoperability server, directly threatens clinical data exchange and patient safety workflows. | Healthcare interoperability at risk: an unauthenticated DoS in HAPI FHIR could halt FHIR-based data exchange between EHRs, labs, and pharmacies. Patch immediately to protect critical clinical workflows. |
| 5 | 2 | CVE-2026-113874 | High-severity authorization bypass in HAPI FHIR enables cross-tenant clinical data access, directly impacting healthcare interoperability infrastructure and multi-tenant data isolation. | Healthcare digital infrastructure alert: A new Tier 2 vulnerability in HAPI FHIR allows authenticated users to bypass tenant partitioning and access sensitive clinical records. Organizations relying on FHIR for interoperability should prioritize patching and gateway validation to protect patient data. |
| 5 | 2 | CVE-2026-114607 | Critical authentication bypass in a core IdAM library enabling session hijacking and account takeover via OAuth/Magic Link token confusion, directly impacting Digital Identity infrastructure. | A critical flaw in the Better Auth library allows attackers to hijack sessions and bypass email verification by exploiting a token confusion bug between OAuth and Magic Link flows. Organizations relying on modern identity stacks should patch immediately to protect user accounts and authentication endpoints. |
| 5 | 2 | CVE-2026-114615 | Core Python library for OAuth/OIDC identity services; authentication bypass allows arbitrary JWT forgery, directly impacting digital identity infrastructure. | A critical authentication bypass in Authlib (CVE-2026-114615) lets attackers forge JWTs with arbitrary claims, threatening OAuth/OIDC identity providers. Upgrade to v1.9.0 or pin algorithms immediately to protect your digital identity stack. |
| 5 | 2 | CVE-2026-114616 | Core Python library for OAuth 2.0/OIDC identity providers; empty-key JWT forgery enables complete authentication bypass in public-sector and enterprise digital identity systems. | A misconfigured secret in a widely used Python identity library can turn OAuth endpoints into open doors. CVE-2026-114616 shows why strict key validation is non-negotiable for digital public infrastructure. |
| 5 | 2 | CVE-2026-86696 | Directly impacts Digital Identity infrastructure by enabling unauthenticated DoS against internet-exposed SAML Single Logout endpoints, disrupting enterprise and government SSO federation. | A single unauthenticated request can crash an entire Erlang-based SAML service provider. This TIER 2 vulnerability in the esaml library highlights the critical need to patch SSO logout endpoints before identity federation goes dark. |
| 5 | 2 | CVE-2026-93471 | Core SAML/SSO library vulnerability enabling unauthenticated DoS on public-facing identity federation endpoints, directly impacting Digital Identity infrastructure. | A critical flaw in a widely used Erlang SAML library allows attackers to crash identity providers with a simple POST request, highlighting the fragility of public-facing SSO endpoints. Organizations relying on SAML for enterprise or government federation should patch immediately. |
| 5 | 2 | CVE-2026-97785 | Critical unauthenticated privilege escalation in Microsoft Entra Application Proxy, a core Digital Identity/IAM component for government and enterprise remote access. | Unauthenticated attackers can bypass Microsoft Entra Application Proxy controls, threatening the identity gateways that secure government and enterprise remote access. Patching and strict Conditional Access policies are critical for Digital Identity infrastructure. |
| 4 | 2 | CVE-2022-51026 | Critical unauthenticated admin takeover in a database DevOps platform widely used for compliance and change management in regulated Finance, Healthcare, and Government environments. | Database governance tools are the backbone of regulated sector compliance, but a critical auth bypass in Bytebase shows how easily internal DevOps platforms can be fully compromised. Ensure your database change management workflows are patched and network-segmented. |
| 4 | 1 | CVE-2024-58393 | Finance sector relevance due to unauthenticated SQLi exposing payment wallets, bank transfers, and financial commission data in a public-facing e-commerce/MLM platform. | Critical unauthenticated SQL injection in a widely deployed MLM e-commerce platform is being actively exploited in the wild, threatening financial data, user wallets, and payment records. Immediate patching is essential for businesses handling online transactions. |
| 4 | 2 | CVE-2024-58396 | Targets CPA audit management systems used by accounting firms, directly impacting financial compliance and audit data confidentiality. | Unauthenticated path traversal in a widely used CPA audit management system exposes sensitive financial and compliance data. Finance and audit sectors should verify network segmentation and patch immediately. |
| 4 | 2 | CVE-2025-71434 | Unauthenticated SQLi in Weaver E-cology OA platform, widely deployed in Chinese government agencies and state-owned enterprises, with confirmed in-wild exploitation. | Confirmed in-wild exploitation of an unauthenticated SQL injection in Weaver E-cology OA systems highlights risks to government and enterprise digital infrastructure. Network segmentation and patching to v10.76+ are critical to prevent database extraction and credential harvesting. |
| 4 | 2 | CVE-2026-110264 | Foundational CI/CD and source control platform explicitly tied to government, finance, and healthcare deployments; unauthenticated RCE threatens software supply chain and operational resilience across regulated sectors. | Unauthenticated RCE in self-managed GitLab (CVSS 10.0) poses a critical supply chain risk for government, finance, and healthcare CI/CD pipelines. With no workarounds available, immediate patching is essential to protect foundational DevOps infrastructure. |
| 4 | 2 | CVE-2026-110353 | Critical edge load balancer DoS impacting availability of public-facing government, finance, and healthcare infrastructure. | An unauthenticated HTTP/2 DoS in HAProxy poses a direct availability threat to critical public and regulated services. Patch edge load balancers to 3.4.6+ to prevent cascading outages. |
| 4 | 2 | CVE-2026-111497 | Foundational web compression library underpinning Node.js, CDNs, and public-facing servers that host regulated and civic digital services. | A critical, unauthenticated RCE in the Brotli compression library threatens the backbone of modern web infrastructure. Public-facing services relying on Node.js or standard web servers must patch immediately to protect citizen and enterprise data flows. |
| 4 | 2 | CVE-2026-114611 | Directly compromises MDM device identity certificates and authentication workflows, impacting Digital Identity and access management for enterprise and public-sector endpoint fleets. | Unauthenticated MDM certificate forgery in OCO-Server allows attackers to hijack device identities and management records. A critical reminder for public-sector and enterprise IT to patch MDM infrastructure and enforce strict network segmentation. |
| 4 | 2 | CVE-2026-114636 | Critical access-control bypass in Traefik Kubernetes ingress controller, compromising the public-facing networking layer that supports Finance, Healthcare, and Government digital services. | A high-severity authentication bypass in Traefik’s Kubernetes ingress controller allows unauthenticated access to protected backends when SSL passthrough is enabled. Organizations deploying this edge proxy for regulated public services should prioritize patching to safeguard critical infrastructure. |
| 4 | 2 | CVE-2026-114727 | Widely deployed open-source webmail platform handling sensitive organizational communications across Government, Healthcare, and Finance sectors; authenticated RCE poses lateral movement and data exfiltration risks. | Public-facing webmail infrastructure remains a high-value target for regulated sectors. CVE-2026-114727 enables authenticated RCE in Roundcube via image uploads, underscoring the need for strict patching and MIME-type controls in government and healthcare email deployments. |
| 4 | 2 | CVE-2026-114730 | Core enterprise email gateway widely deployed in public sector, healthcare, and finance; SSRF bypass enables internal recon and cloud metadata theft in regulated environments. | Roundcube Webmail’s SSRF filter bypass (CVE-2026-114730) turns a common enterprise email gateway into a reconnaissance tool for attackers targeting public sector and healthcare networks. Patching is critical to prevent internal mapping and cloud metadata theft. |
| 4 | 2 | CVE-2026-115330 | Critical SQLi in self-hosted billing/monetization infrastructure enables cross-tenant financial data theft and revenue manipulation, directly impacting Finance and public-sector billing services. | Billing platforms are the backbone of digital revenue assurance. This critical SQL injection in Lotus (≤0.10.2) allows authenticated users to execute arbitrary stacked SQL, risking cross-tenant data exfiltration and silent financial manipulation. Organizations relying on usage-based billing or citizen service monetization should patch immediately and enforce least-privilege database roles. |
| 4 | 2 | CVE-2026-115331 | Critical SQL injection in open-source billing and subscription infrastructure compromises multi-tenant financial data and payment operations. | A critical SQLi in popular open-source billing infrastructure (Lotus) exposes multi-tenant financial data and subscription records. Finance and SaaS teams should patch immediately to protect revenue operations and customer account integrity. |
| 4 | 2 | CVE-2026-115332 | Finance sector relevance: SQLi in open-source billing/metering infrastructure compromises multi-tenant financial data and invoicing integrity. | A TIER 2 SQL injection in Lotus billing infrastructure exposes multi-tenant financial records and invoicing data. Organizations relying on open-source pricing stacks should patch immediately to protect revenue tracking and tenant confidentiality. |
| 4 | 2 | CVE-2026-115333 | Finance sector relevance: improper authentication in a metering/billing platform allows forged usage events, directly impacting financial integrity and revenue operations. | A Tier 2 flaw in the Lotus metering platform shows how weak API key validation can directly compromise financial integrity. For DPI and regulated services, this underscores the critical need for robust authentication in billing and transaction ingestion endpoints. |
| 4 | 2 | CVE-2026-115334 | Finance sector relevance: multi-tenant billing/metering platform vulnerability enabling cross-tenant access to invoices, subscriptions, and payment data. | Multi-tenant billing platforms are critical financial infrastructure, but a missing authorization check in Lotus could let attackers hijack tenant accounts and access sensitive invoice and payment data. Organizations relying on open-source metering stacks should prioritize patching to protect revenue assurance and customer financial records. |
| 4 | 2 | CVE-2026-83938 | Critical missing authentication in Azure Kubernetes Configuration Service impacts foundational cloud orchestration underpinning regulated finance, healthcare, government, and identity deployments. | Unauthenticated privilege escalation in Azure’s Kubernetes configuration layer (CVSS 10.0) poses systemic risk to cloud-hosted public and regulated services. Organizations relying on AKS for critical infrastructure should prioritize monitoring and patch readiness as Microsoft addresses this foundational control plane flaw. |
| 3 | 1 | CVE-2021-48017 | Tier 1 unauthenticated path traversal in a collaboration/groupware platform explicitly noted for public sector and government deployment, enabling credential harvesting and network pivoting. | Public-facing collaboration servers are prime targets: CVE-2021-48017 is a Tier 1, actively exploited path traversal flaw in OrbiTeam BSCW that requires zero authentication. Government and enterprise teams using this groupware for remote access should patch immediately to prevent credential harvesting and lateral movement. |
| 3 | 2 | CVE-2026-105014 | TIER 2 command injection in Azure Pipelines CI/CD tasks threatens supply chain integrity and credential security for regulated enterprise and public-sector deployments. | A critical RCE in Microsoft Azure Pipelines build tasks highlights the growing attack surface of cloud CI/CD infrastructure. For DPI and regulated sectors, securing pipeline triggers and auditing task inputs is now a supply chain imperative. |
| 3 | 2 | CVE-2026-108357 | General infrastructure PHP library widely deployed in government and enterprise data portals, enabling DoS and SSRF via crafted spreadsheet uploads. | A TIER 2 vulnerability in the widely used PhpSpreadsheet library allows attackers to bypass XML security scanning, risking DoS or SSRF in government and enterprise data ingestion portals. Patching is essential for any public-facing application handling file uploads. |
| 3 | 2 | CVE-2026-110354 | Foundational load balancer vulnerability impacting public-facing infrastructure widely deployed in government and regulated enterprise environments. | An unauthenticated DoS in HAProxy threatens the availability of public-facing digital services. As a core component of government and enterprise edge infrastructure, timely patching is essential to prevent widespread service disruption. |
| 3 | 2 | CVE-2026-114625 | Actively exploited SQLi in critical SD-WAN orchestration infrastructure frequently deployed by government and financial sectors. | Active exploitation of a critical SQL injection in Arista SD-WAN orchestrators highlights urgent patching needs for public and financial sector networks. Restrict admin access and enforce MFA immediately. |
| 3 | 2 | CVE-2026-114640 | General infrastructure: Kubernetes ingress controller foundational to cloud-native DPI, with mTLS bypass risk impacting regulated service gateways. | CVE-2026-114640 in Traefik shows how non-default ingress configurations can undermine mTLS in cloud-native DPI. Patching and strict annotation policies are essential for protecting government and enterprise edge proxies. |
| 3 | 2 | CVE-2026-115384 | Critical sandbox escape in Wasmtime runtime impacts cloud-native and serverless infrastructure underpinning regulated sector workloads. | A critical stack buffer overflow in Wasmtime (CVE-2026-115384) allows malicious WebAssembly components to escape sandboxes and achieve RCE. While requiring specific async features, this Tier 2 vulnerability underscores the need for strict runtime validation in cloud-native and regulated infrastructure deployments. |
| 3 | 2 | CVE-2026-115450 | Finance sector relevance: directly compromises payment processing integrity and transaction execution in digital commerce platforms, enabling systematic financial theft. | A TIER 2 business logic flaw in a widely used e-commerce template demonstrates how client-side price manipulation can bypass payment gateways. For digital commerce and financial infrastructure, this reinforces why server-side transaction validation is critical to prevent direct monetary loss. |
| 3 | 2 | CVE-2026-92709 | Foundational logging infrastructure deployed across government and critical infrastructure environments, requiring configuration hardening to prevent arbitrary file writes. | rsyslog remains a backbone for government and critical infrastructure logging, but a path traversal flaw in dynamic file templates highlights the need for strict secure-path configurations. Operators should audit dynaFile templates and enforce least-privilege logging to protect audit trails. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-106017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110063.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110491.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112085.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112331.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114221.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114510.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114519.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114605.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114638.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114644.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114648.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114649.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114661.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114665.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115352.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115353.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115365.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115373.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115377.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115414.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115416.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115419.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16477.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61791.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96616.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97631.md` — heuristic TIER 3/4
