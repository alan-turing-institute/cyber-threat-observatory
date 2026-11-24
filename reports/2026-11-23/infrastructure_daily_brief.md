# **Infrastructure Daily Brief: 2026-11-23**

**Infrastructure Daily Report TLP:GREEN Alert Id: e3e7b4bb 2026-11-24 10:08:48**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-101862 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-101863 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-101870 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109490 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135157 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135175 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135300 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-101864 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-101866 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-101867 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-101868 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-101869 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-101872 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129975 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135160 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135164 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135239 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135258 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-50691 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-70193 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82979 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82981 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93700 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-118285 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-133469 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134842 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-135249 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-123886 (Tier 2)                                                         | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.j.3    |
| Threats    | The risks of device code authentication for AI coding agents                     | 1.j.3    |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.d      |
| Threats    | Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK                      | 1.j.3    |
| Threats    | Device Code Phishing: An Evolving Technique Impacting SLTTs                      | 1.j.3    |
| Threats    | Access granted: phishing with device code authorization for account takeover     | 1.j.3    |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.a      |
| Threats    | Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and | 1.a      |
| Threats    | CVE-2026-135163                                                                  | 1.b      |
| Threats    | CVE-2026-96457                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-23

Researchers expose the EvilTokens toolkit, which automates device code phishing attacks to bypass multi-factor authentication. The report outlines attack flows, token interception techniques, and mitigation strategies for identity administrators. Defenders should review conditional access policies, monitor for suspicious device code requests, and educate users on verifying authorization prompts.

___________________________________


# **[The risks of device code authentication for AI coding agents](https://microsoft.com/en-us/security/blog/2026/11/17/the-risks-of-device-code-authentication-for-ai-coding-agents)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-23

As AI coding assistants proliferate, attackers are exploiting device code flows to compromise developer accounts and CI/CD pipelines. This advisory highlights how malicious actors trick developers into authorizing rogue tokens, leading to supply chain and infrastructure breaches. Defenders should enforce strict app registration scopes, monitor for unusual device code grants, and restrict AI agent permissions.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.d**

Source: ketch Published: 2026-11-23

This analysis dissects the underground infrastructure supporting large-scale phishing operations, detailing how threat actors leverage bulletproof hosting, domain generation algorithms, and proxy networks to evade detection. IT defenders can use these insights to enhance DNS filtering, implement advanced URL reputation checks, and monitor for anomalous certificate deployments across their environments.

___________________________________


# **[Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-23

This technical breakdown tracks the BigBear 2.0 campaign utilizing the Evilginx2 reverse proxy framework to harvest session cookies and bypass MFA. The article provides IOCs, proxy architecture details, and detection rules for SIEM and proxy logs. Infrastructure teams can leverage these indicators to block malicious proxy domains and implement certificate pinning where feasible.

___________________________________


# **[Device Code Phishing: An Evolving Technique Impacting SLTTs](https://cisecurity.org/insights/blog/device-code-phishing-evolving-technique-impacting-sltts)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-23

State, local, tribal, and territorial governments face escalating device code phishing attacks targeting cloud identity platforms. The report details campaign trends, common lures, and architectural vulnerabilities in OAuth flows. IT leaders are advised to deploy phishing-resistant MFA, implement continuous access evaluation, and establish rapid incident response playbooks for compromised service accounts.

___________________________________


# **[Access granted: phishing with device code authorization for account takeover](https://proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-23

This threat intelligence report examines how adversaries leverage device code authorization pages to conduct account takeovers without traditional credential harvesting. Attackers manipulate QR codes and verification URLs to trick users into granting full access. Defenders should monitor for high-frequency device code requests, enforce step-up authentication for sensitive actions, and deploy browser-based detection controls.

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.a**

Source: ketch Published: 2026-11-23

A Five Eyes joint advisory warns of coordinated spear-phishing operations by state-sponsored actors targeting energy, transportation, and healthcare sectors. The campaign uses highly tailored lures, malicious macros, and living-off-the-land techniques. Infrastructure defenders should prioritize email gateway filtering, disable unnecessary macro execution, and segment critical OT/IT networks to limit lateral movement.

___________________________________


# **[Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a)**

**PIR: 1.a**

Source: ketch Published: 2026-11-23

CISA details a persistent spear-phishing campaign exploiting compromised legitimate credentials and fake login portals to infiltrate diplomatic and governmental networks. The advisory provides technical indicators, email header analysis, and recommended mitigations. Security teams should validate inbound email authentication, enforce least privilege access, and conduct regular phishing simulations for high-value targets.

___________________________________


# **[CVE-2026-135163](https://nvd.nist.gov/vuln/detail/CVE-2026-135163)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-23

Okou API before 1.762.0 contains a missing authentication vulnerability in its Microsoft Teams, legacy Slack, and GitHub App integration OAuth flows that trusts caller-supplied userId and orgId values. Unauthenticated attackers who know a member's identifiers can complete the flow with their own external account to bind that identity or installation to the victim's Okou user and organization.

___________________________________


# **[CVE-2026-96457](https://nvd.nist.gov/vuln/detail/CVE-2026-96457)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-23

A flaw was found in the administrative interface of Keycloak, an identity and access management solution. The issue occurs when Fine-Grained Admin Permissions are used to restrict a group administrator from managing specific sub-groups. Due to an incomplete fix for a previous vulnerability, a restricted administrator can bypass these restrictions by moving a forbidden sub-group to the top level of the hierarchy. This allows the attacker to gain unauthorized control over the groups members, poten

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-101862 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101862)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Government sector: Official EU public consultation platform (European Commission/Parliament) with authenticated RCE impacting civic engagement infrastructure and public sector data integrity.

*Deep dive: `TIER_2_CVE-2026-101862.md`*

___________________________________


# **[CVE-2026-101863 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101863)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Directly impacts Government DPI by compromising EU public consultation platforms, risking manipulation of citizen feedback and undermining democratic engagement processes.

*Deep dive: `TIER_2_CVE-2026-101863.md`*

___________________________________


# **[CVE-2026-101870 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101870)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Unauthenticated authorization bypass in the EU Commission's EUSurvey platform compromises the integrity of public consultations and civic engagement data.

*Deep dive: `TIER_2_CVE-2026-101870.md`*

___________________________________


# **[CVE-2026-109490 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109490)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Directly impacts Microsoft Entra, a foundational cloud IdAM platform, enabling session hijacking and privilege escalation in Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-109490.md`*

___________________________________


# **[CVE-2026-135157 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135157)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Directly compromises SAML authentication and IdP configurations in multi-tenant environments, breaking cross-tenant identity isolation.

*Deep dive: `TIER_2_CVE-2026-135157.md`*

___________________________________


# **[CVE-2026-135175 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135175)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Critical host header injection in ZITADEL IdP enables full account takeover and MFA bypass, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-135175.md`*

___________________________________


# **[CVE-2026-135300 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135300)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Critical authentication bypass in Pomerium zero-trust proxy undermines SSO and OAuth/OIDC token validation, directly impacting Digital Identity infrastructure for public and regulated sectors.

*Deep dive: `TIER_2_CVE-2026-135300.md`*

___________________________________


# **[CVE-2026-101864 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101864)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Government sector relevance; account takeover flaw in the EU Commission's EUSurvey platform used for public consultations and civic engagement.

*Deep dive: `TIER_2_CVE-2026-101864.md`*

___________________________________


# **[CVE-2026-101866 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101866)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Directly impacts EU government eParticipation and citizen consultation platforms by allowing unauthenticated draft manipulation and token theft.

*Deep dive: `TIER_2_CVE-2026-101866.md`*

___________________________________


# **[CVE-2026-101867 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101867)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

TIER 2 authorization flaw in EUSurvey, the official survey platform for the European Commission and EU institutions, risking PII exposure and disruption of public consultations.

*Deep dive: `TIER_2_CVE-2026-101867.md`*

___________________________________


# **[CVE-2026-101868 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101868)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Government sector: unauthenticated authorization bypass in the European Commission's official public consultation platform exposes citizen survey data.

*Deep dive: `TIER_2_CVE-2026-101868.md`*

___________________________________


# **[CVE-2026-101869 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101869)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Unauthenticated SQLi in EUSurvey, the EU Commission's primary platform for public consultations and citizen engagement, risking cross-survey data leakage and GDPR compliance.

*Deep dive: `TIER_2_CVE-2026-101869.md`*

___________________________________


# **[CVE-2026-101872 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101872)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Government sector: EU institutions deploy EUSurvey for citizen consultations and public feedback, making this authenticated SQLi a direct risk to civic data and public-sector digital services.

*Deep dive: `TIER_2_CVE-2026-101872.md`*

___________________________________


# **[CVE-2026-129975 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129975)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Core cryptographic library (GPGME) underpinning OpenPGP-based digital signatures, secure communications, and identity verification in government and regulated enterprise environments.

*Deep dive: `TIER_2_CVE-2026-129975.md`*

___________________________________


# **[CVE-2026-135160 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135160)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Impacts Healthcare DPI by compromising clinical data integrity and cross-project isolation in Medplum FHIR backends used by regulated health information systems.

*Deep dive: `TIER_2_CVE-2026-135160.md`*

___________________________________


# **[CVE-2026-135164 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135164)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

High-severity SQL injection in Formance Ledger, a distributed ledger system for CBDCs and payment infrastructure, directly threatens financial data integrity and confidentiality.

*Deep dive: `TIER_2_CVE-2026-135164.md`*

___________________________________


# **[CVE-2026-135239 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135239)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Government sector relevance: Authorization bypass in MISP compromises data integrity and attribution trust for national CERTs and government agencies sharing threat intelligence.

*Deep dive: `TIER_2_CVE-2026-135239.md`*

___________________________________


# **[CVE-2026-135258 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135258)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

TIER 2 authorization bypass and path traversal in MISP, a core threat intelligence platform widely deployed by government CSIRTs, financial sector ISACs, and healthcare networks for secure data sharing.

*Deep dive: `TIER_2_CVE-2026-135258.md`*

___________________________________


# **[CVE-2026-50691 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-50691)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Critical privilege escalation in Microsoft 365 Copilot, a foundational SaaS AI tool widely deployed across government, finance, and healthcare sectors, with authentication tied to Microsoft Entra ID.

*Deep dive: `TIER_2_CVE-2026-50691.md`*

___________________________________


# **[CVE-2026-70193 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-70193)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Critical RCE in Microsoft SharePoint impacts enterprise collaboration widely deployed across Government, Finance, and Healthcare for internal operations and citizen services.

*Deep dive: `TIER_2_CVE-2026-70193.md`*

___________________________________


# **[CVE-2026-82979 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82979)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Finance sector relevance: WHMCS is a widely deployed billing and payment processing platform for service providers, handling financial transactions and client account data.

*Deep dive: `TIER_2_CVE-2026-82979.md`*

___________________________________


# **[CVE-2026-82981 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82981)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Unauthenticated SQLi in WHMCS exposes client PII and payment data in internet-facing billing portals used by ISPs and cloud infrastructure providers.

*Deep dive: `TIER_2_CVE-2026-82981.md`*

___________________________________


# **[CVE-2026-93700 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93700)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Critical RCE in WHMCS billing platform impacts Finance and General Infrastructure by compromising payment processing, customer accounts, and hosting provider infrastructure.

*Deep dive: `TIER_2_CVE-2026-93700.md`*

___________________________________


# **[CVE-2026-118285 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-118285)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Foundational cloud AI/ML infrastructure with explicit cross-sector applicability to regulated environments (Healthcare, Finance, Government), requiring strict IAM and network isolation to prevent post-compromise privilege escalation.

*Deep dive: `TIER_2_CVE-2026-118285.md`*

___________________________________


# **[CVE-2026-133469 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-133469)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

TIER 2 hypervisor management plane bypass with active wild exploitation; foundational virtualization infrastructure underpins regulated enterprise and public-sector workloads.

*Deep dive: `TIER_2_CVE-2026-133469.md`*

___________________________________


# **[CVE-2026-134842 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134842)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Foundational PostgreSQL JDBC driver SQLi impacting backend connectivity across regulated sectors, mitigated by default config hardening.

*Deep dive: `TIER_2_CVE-2026-134842.md`*

___________________________________


# **[CVE-2026-135249 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-135249)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

Unauthenticated DoS in MISP threat intelligence platform, explicitly tied to government CSIRTs, financial ISACs, and healthcare security operations.

*Deep dive: `TIER_2_CVE-2026-135249.md`*

___________________________________


# **[CVE-2026-123886 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123886)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-23

High-severity RCE in a foundational enterprise Java framework widely deployed across public-sector and regulated API backends.

*Deep dive: `TIER_2_CVE-2026-123886.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine