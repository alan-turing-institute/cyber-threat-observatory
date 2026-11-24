# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-24 10:08:48Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-23`
- **Included count:** 28

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-101862 | Government sector: Official EU public consultation platform (European Commission/Parliament) with authenticated RCE impacting civic engagement infrastructure and public sector data integrity. | A TIER 2 authenticated RCE in EUSurvey highlights the risks to civic engagement infrastructure. As the official survey platform for EU institutions, this path-traversal flaw underscores the need for strict access controls and patching in government-facing digital services. |
| 5 | 2 | CVE-2026-101863 | Directly impacts Government DPI by compromising EU public consultation platforms, risking manipulation of citizen feedback and undermining democratic engagement processes. | A TIER 2 authorization flaw in the EU Commission’s EUSurvey platform could allow authenticated users to hijack or delete public consultations, threatening the integrity of citizen engagement and democratic feedback loops. Government agencies relying on digital consultation tools should prioritize patching and endpoint monitoring. |
| 5 | 2 | CVE-2026-101870 | Unauthenticated authorization bypass in the EU Commission's EUSurvey platform compromises the integrity of public consultations and civic engagement data. | A Tier 2 vulnerability in the European Commission's official public consultation platform allows unauthenticated attackers to overwrite citizen survey responses, posing a direct threat to the integrity of EU democratic feedback processes. |
| 5 | 2 | CVE-2026-109490 | Directly impacts Microsoft Entra, a foundational cloud IdAM platform, enabling session hijacking and privilege escalation in Digital Identity infrastructure. | A critical XSS flaw in Microsoft Entra’s Authentication Methods Portal could let attackers hijack sessions and escalate privileges in cloud identity tenants. For DPI and regulated sectors relying on Entra for access control, patching and enforcing phishing-resistant MFA are immediate priorities. |
| 5 | 2 | CVE-2026-135157 | Directly compromises SAML authentication and IdP configurations in multi-tenant environments, breaking cross-tenant identity isolation. | Multi-tenant SAML bypass in Future AGI allows low-privilege users to hijack cross-tenant accounts and manipulate IdP settings. Critical patch for digital identity and enterprise SSO deployments. |
| 5 | 2 | CVE-2026-135175 | Critical host header injection in ZITADEL IdP enables full account takeover and MFA bypass, directly impacting Digital Identity infrastructure. | A TIER 2 vulnerability in ZITADEL (CVE-2026-135175) shows how a single manipulated header can bypass MFA and hijack identity recovery flows. For any organization relying on public-facing IdPs, patching to v4.20.3+ or hardening reverse proxies is now essential to protect digital identity infrastructure. |
| 5 | 2 | CVE-2026-135300 | Critical authentication bypass in Pomerium zero-trust proxy undermines SSO and OAuth/OIDC token validation, directly impacting Digital Identity infrastructure for public and regulated sectors. | A critical flaw in Pomerium’s zero-trust proxy allows attackers to bypass client secret validation and redeem intercepted OAuth tokens, threatening the integrity of SSO and identity-aware routing in government and enterprise environments. Patch to v0.34.0+ immediately to protect your digital identity perimeter. |
| 4 | 2 | CVE-2026-101864 | Government sector relevance; account takeover flaw in the EU Commission's EUSurvey platform used for public consultations and civic engagement. | A logic flaw in the EU's EUSurvey platform could allow attackers to hijack accounts via stale password-reset links, threatening the integrity of public consultations and citizen feedback channels. This underscores the need for robust authentication safeguards in government-facing digital infrastructure. |
| 4 | 2 | CVE-2026-101866 | Directly impacts EU government eParticipation and citizen consultation platforms by allowing unauthenticated draft manipulation and token theft. | EU institutions relying on EUSurvey for citizen consultations face a critical integrity risk: an unauthenticated bypass lets attackers overwrite survey drafts and steal invitation tokens. Patching is urgent to protect public trust in digital government engagement. |
| 4 | 2 | CVE-2026-101867 | TIER 2 authorization flaw in EUSurvey, the official survey platform for the European Commission and EU institutions, risking PII exposure and disruption of public consultations. | EU institutions relying on EUSurvey for public consultations should patch immediately: a TIER 2 authorization flaw allows authenticated users to access and modify other users' contact shares, risking PII leaks and survey disruption. |
| 4 | 2 | CVE-2026-101868 | Government sector: unauthenticated authorization bypass in the European Commission's official public consultation platform exposes citizen survey data. | Public consultations are a cornerstone of digital democracy, but an unauthenticated bypass in the EU's official survey platform could expose sensitive citizen feedback. Patching EUSurvey instances is critical to protect government-citizen engagement channels. |
| 4 | 2 | CVE-2026-101869 | Unauthenticated SQLi in EUSurvey, the EU Commission's primary platform for public consultations and citizen engagement, risking cross-survey data leakage and GDPR compliance. | Governments relying on EUSurvey for citizen consultations face a high-impact SQL injection flaw that could leak private respondent data across surveys. Patching is critical to protect civic engagement infrastructure and maintain public trust. |
| 4 | 2 | CVE-2026-101872 | Government sector: EU institutions deploy EUSurvey for citizen consultations and public feedback, making this authenticated SQLi a direct risk to civic data and public-sector digital services. | A blind SQLi in the European Commission’s EUSurvey platform highlights how authenticated flaws in citizen engagement tools can expose sensitive public consultation data. Patching and strict access controls are critical for government-facing digital infrastructure. |
| 4 | 2 | CVE-2026-129975 | Core cryptographic library (GPGME) underpinning OpenPGP-based digital signatures, secure communications, and identity verification in government and regulated enterprise environments. | A critical double-free in GPGME could compromise the cryptographic foundations of digital identity and secure government communications. Patching this TIER 2 vulnerability is essential for any infrastructure relying on OpenPGP for authentication and document signing. |
| 4 | 2 | CVE-2026-135160 | Impacts Healthcare DPI by compromising clinical data integrity and cross-project isolation in Medplum FHIR backends used by regulated health information systems. | Healthcare data integrity alert: CVE-2026-135160 allows authenticated users to overwrite clinical documents in Medplum FHIR backends. Upgrade to v5.1.42+ to preserve cross-project isolation in health information exchanges. |
| 4 | 2 | CVE-2026-135164 | High-severity SQL injection in Formance Ledger, a distributed ledger system for CBDCs and payment infrastructure, directly threatens financial data integrity and confidentiality. | A critical SQL injection flaw in Formance Ledger exposes distributed financial ledgers and CBDC infrastructure to data breaches and integrity loss. Finance teams and public sector digital currency initiatives should prioritize patching to v2.4.18 to safeguard transactional trust. |
| 4 | 2 | CVE-2026-135239 | Government sector relevance: Authorization bypass in MISP compromises data integrity and attribution trust for national CERTs and government agencies sharing threat intelligence. | Government CSIRTs and national CERTs should prioritize upgrading MISP to 2.5.52 to prevent authenticated users from poisoning threat intelligence feeds and undermining cross-agency attribution trust. |
| 4 | 2 | CVE-2026-135258 | TIER 2 authorization bypass and path traversal in MISP, a core threat intelligence platform widely deployed by government CSIRTs, financial sector ISACs, and healthcare networks for secure data sharing. | MISP remains a backbone for national cybersecurity centers and regulated sector ISACs. This TIER 2 flaw highlights how internal trust boundaries and permission models must be hardened to protect shared threat intelligence across government and critical infrastructure networks. |
| 4 | 2 | CVE-2026-50691 | Critical privilege escalation in Microsoft 365 Copilot, a foundational SaaS AI tool widely deployed across government, finance, and healthcare sectors, with authentication tied to Microsoft Entra ID. | Microsoft 365 Copilot faces a critical authorization flaw (CVE-2026-50691) that allows authenticated users to escalate privileges within the AI environment. While it requires valid credentials, the impact on government and financial tenants relying on Entra ID for access control warrants immediate monitoring and least-privilege enforcement. |
| 4 | 2 | CVE-2026-70193 | Critical RCE in Microsoft SharePoint impacts enterprise collaboration widely deployed across Government, Finance, and Healthcare for internal operations and citizen services. | Microsoft SharePoint faces a critical path traversal flaw enabling remote code execution for authenticated users. With widespread adoption across government, finance, and healthcare for citizen services and internal operations, organizations must prioritize patching and enforce strict access controls to protect critical digital infrastructure. |
| 4 | 2 | CVE-2026-82979 | Finance sector relevance: WHMCS is a widely deployed billing and payment processing platform for service providers, handling financial transactions and client account data. | A TIER 2 SQL injection in WHMCS exposes client billing data and admin credentials, highlighting risks to the financial and hosting infrastructure that underpins digital service delivery. Patching is critical for providers managing regulated payment and account workflows. |
| 4 | 2 | CVE-2026-82981 | Unauthenticated SQLi in WHMCS exposes client PII and payment data in internet-facing billing portals used by ISPs and cloud infrastructure providers. | Unauthenticated SQL injection in WHMCS (CVE-2026-82981) allows attackers to extract client PII and payment data from internet-facing billing portals. ISPs and cloud providers should patch immediately to protect financial operations and customer trust. |
| 4 | 2 | CVE-2026-93700 | Critical RCE in WHMCS billing platform impacts Finance and General Infrastructure by compromising payment processing, customer accounts, and hosting provider infrastructure. | Hosting providers and digital service platforms running WHMCS face a critical RCE risk that could compromise billing systems and customer payment data. Patching or disabling email campaigns is essential to protect financial operations and underlying infrastructure. |
| 3 | 2 | CVE-2026-118285 | Foundational cloud AI/ML infrastructure with explicit cross-sector applicability to regulated environments (Healthcare, Finance, Government), requiring strict IAM and network isolation to prevent post-compromise privilege escalation. | A critical SSRF in Azure Machine Learning underscores how foundational cloud AI platforms amplify risk across regulated sectors. Enforcing least-privilege IAM and private endpoints is essential to contain post-compromise escalation in government, finance, and healthcare deployments. |
| 3 | 2 | CVE-2026-133469 | TIER 2 hypervisor management plane bypass with active wild exploitation; foundational virtualization infrastructure underpins regulated enterprise and public-sector workloads. | Active wild exploitation of Xen Orchestra’s authentication bypass grants unauthenticated root RCE on XCP-ng pools. While designed for internal management networks, this TIER 2 vulnerability highlights the critical need for strict network isolation and rapid patching in foundational virtualization stacks supporting regulated environments. |
| 3 | 2 | CVE-2026-134842 | Foundational PostgreSQL JDBC driver SQLi impacting backend connectivity across regulated sectors, mitigated by default config hardening. | A TIER 2 SQL injection in the PostgreSQL JDBC driver shows how legacy database settings can expose critical backend infrastructure. DPI operators should verify default query modes and string handling to protect regulated data pipelines. |
| 3 | 2 | CVE-2026-135249 | Unauthenticated DoS in MISP threat intelligence platform, explicitly tied to government CSIRTs, financial ISACs, and healthcare security operations. | A trivially exploitable DoS in MISP could silence critical threat intelligence feeds for government CSIRTs and financial ISACs. Enforcing proxy-level compression limits or patching is essential to keep cross-sector security operations resilient. |
| 2 | 2 | CVE-2026-123886 | High-severity RCE in a foundational enterprise Java framework widely deployed across public-sector and regulated API backends. | A SpEL injection flaw in Spring Data Elasticsearch (CVE-2026-123886) demonstrates how a single library vulnerability can compromise entire public-facing Java stacks. Organizations relying on Elasticsearch-backed APIs should prioritize patching or refactoring query methods to prevent remote code execution. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-101219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103782.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109480.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115873.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115899.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115903.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-119069.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120747.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-121456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130165.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130166.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130167.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132257.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133960.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133961.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134620.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134850.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135055.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135173.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96457.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-103786.md` — heuristic TIER 3/4
