# **Infrastructure Daily Brief: 2026-11-13**

**Infrastructure Daily Report TLP:GREEN Alert Id: e4a14d07 2026-11-15 03:46:55**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-107412 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107413 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-126451 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-126487 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-126488 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129110 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-59074 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2024-58406 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-102612 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107407 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107408 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107409 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107411 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-107415 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111334 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111337 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111341 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111342 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-120864 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-120865 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-120867 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-124679 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-126091 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-126429 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-126454 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-127090 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-127278 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-127279 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-128041 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-82504 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-107410 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-123975 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-124680 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-128049 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129180 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-62976 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-97692 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-100403 (Tier 2)                                                         | 3.k      |
| Threats    | The Hidden Relay: Inside a Device Code Phishing Kit That Never Shows the Code    | 1.b      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.c      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.d      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.b      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing           | 1.b      |
| Threats    | Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM | 1.a      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.b      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale              | 1.a      |
| Threats    | CVE-2026-120869                                                                  | 1.b      |
| Threats    | CVE-2026-19422                                                                   | 1.b      |
| Threats    | CVE-2026-75869                                                                   | 1.b      |
| Threats    | CVE-2026-19421                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The Hidden Relay: Inside a Device Code Phishing Kit That Never Shows the Code](https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code)**

**PIR: 1.b**

Source: ketch Published: 2026-11-13

Analyzes a novel device code phishing kit that bypasses traditional detection by never exposing the authorization code to the victim. Attackers use a hidden relay proxy to silently capture OAuth tokens, enabling seamless account takeover. Infrastructure defenders should monitor for anomalous OAuth consent requests, enforce conditional access policies requiring compliant devices, and deploy AI-driven behavioral analytics to detect proxy-mediated authentication flows.

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.c**

Source: ketch Published: 2026-11-13

Outlines coordinated campaigns by nation-state actors targeting critical infrastructure via highly tailored spearphishing emails with malicious RDP and document attachments. The advisory emphasizes the need for email gateway filtering, endpoint isolation, and strict remote access controls to prevent initial foothold and lateral movement across OT/IT networks. Defenders should prioritize threat hunting for known APT TTPs and harden remote management protocols.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime)**

**PIR: 1.d**

Source: ketch Published: 2026-11-13

Maps the underground infrastructure supporting global phishing operations, revealing how threat actors leverage bulletproof hosting, domain generation algorithms, and compromised legitimate services to evade takedowns. Defenders must implement DNS sinkholing, integrate threat intelligence feeds for known phishing domains, and deploy network-level blocking rules to disrupt command-and-control channels before credential harvesting occurs.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.b**

Source: ketch Published: 2026-11-13

Reveals how attackers integrate generative AI to dynamically craft phishing pages and automate device code authorization prompts. The campaign adapts in real-time to bypass WAF rules and user suspicion. Infrastructure teams should deploy AI-resistant CAPTCHAs, monitor for rapid consent request spikes, and enforce strict app registration policies in identity providers to mitigate automated token theft.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.b**

Source: ketch Published: 2026-11-13

Details a campaign exploiting the device code flow to bypass password-based MFA and credential theft defenses. Attackers trick users into authorizing malicious apps, granting full tenant access. IT teams should restrict device code grant types in Azure AD, enforce risk-based conditional access, and monitor for high-privilege token issuance from unfamiliar IP ranges to prevent identity compromise.

___________________________________


# **[Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise](https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise)**

**PIR: 1.a**

Source: ketch Published: 2026-11-13

Examines a multi-stage campaign using fake compliance portals to harvest OAuth tokens via AiTM proxies. The attack chain combines social engineering with automated token relay to defeat step-up authentication. Defenders should implement token binding, restrict third-party app consent, and deploy user training focused on recognizing spoofed corporate policy pages to block session hijacking.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-11-13

Explores how device code phishing has matured into a primary identity takeover vector, circumventing traditional password stealers. The article outlines detection strategies including monitoring for unusual device code grant patterns, enforcing hardware-backed MFA, and implementing zero-trust network access controls to limit lateral movement post-compromise across enterprise environments.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale)**

**PIR: 1.a**

Source: ketch Published: 2026-11-13

Dissects the Tycoon2FA AiTM kit, highlighting its modular architecture and automated proxy relay capabilities that capture live session cookies. The analysis provides IOCs and detection rules for SIEM integration. Defenders should prioritize blocking known AiTM domains, enforce certificate pinning for critical apps, and implement continuous authentication monitoring to detect anomalous session behavior.

___________________________________


# **[CVE-2026-120869](https://nvd.nist.gov/vuln/detail/CVE-2026-120869)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-12

An unauthenticated attacker can bypass authentication controls to access restricted resources on the Citrix NetScaler Console appliance

___________________________________


# **[CVE-2026-19422](https://nvd.nist.gov/vuln/detail/CVE-2026-19422)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-12

Zohocorp ManageEngine DDI Central versions below 6301 is affected by an authentication bypass vulnerability in Windows DNS and DHCP agent synchronization APIs, allowing unauthenticated user to impersonate onboarded Windows servers and perform unauthorized DNS and DHCP modifications.

___________________________________


# **[CVE-2026-75869](https://nvd.nist.gov/vuln/detail/CVE-2026-75869)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-12

Zohocorp ManageEngine DDI Central versions below 6301 is affected by an authorization bypass and PowerShell command injection vulnerability that allowed authenticated non-administrative users to target unauthorized Windows DHCP subnets and potentially execute arbitrary commands on managed Windows DHCP servers through crafted DNS suffix values.

___________________________________


# **[CVE-2026-19421](https://nvd.nist.gov/vuln/detail/CVE-2026-19421)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-12

Zohocorp ManageEngine DDI Central versions below 6301 is affected by a PowerShell injection vulnerability due to insufficient validation of user-supplied TXT record values in Windows DNS operations.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-107412 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107412)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Directly impacts Citrix NetScaler AAA virtual servers, a core Digital Identity and remote access component widely deployed across government, healthcare, and finance sectors.

*Deep dive: `TIER_2_CVE-2026-107412.md`*

___________________________________


# **[CVE-2026-107413 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107413)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Directly impacts SAML-based SSO authentication availability on widely deployed enterprise gateways, affecting Digital Identity, Government, Healthcare, and Finance sectors.

*Deep dive: `TIER_2_CVE-2026-107413.md`*

___________________________________


# **[CVE-2026-126451 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126451)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Stored XSS in OpenEMR patient portals enables PHI exfiltration and staff session hijack, directly impacting healthcare digital infrastructure and HIPAA compliance.

*Deep dive: `TIER_2_CVE-2026-126451.md`*

___________________________________


# **[CVE-2026-126487 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126487)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Healthcare sector: Authorization bypass in widely deployed OpenEMR EHR system undermines HIPAA audit compliance and clinical data security.

*Deep dive: `TIER_2_CVE-2026-126487.md`*

___________________________________


# **[CVE-2026-126488 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126488)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Healthcare sector: SQL injection in OpenEMR patient portal allows authenticated users to exfiltrate full database including PHI and staff hashes.

*Deep dive: `TIER_2_CVE-2026-126488.md`*

___________________________________


# **[CVE-2026-129110 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129110)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Unauthenticated RCE in sysPass, a centralized credential vault, directly threatens Digital Identity workflows and institutional access controls across Government, Finance, and Healthcare.

*Deep dive: `TIER_2_CVE-2026-129110.md`*

___________________________________


# **[CVE-2026-59074 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59074)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

JWT signature bypass in Edito CMS enables authenticated privilege escalation to admin, directly impacting Digital Identity, Finance (e-commerce/B2B), and Government (citizen portals) deployments.

*Deep dive: `TIER_2_CVE-2026-59074.md`*

___________________________________


# **[CVE-2024-58406 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2024-58406)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Widely deployed across Chinese government agencies and state-owned enterprises; unauthenticated path traversal enables credential theft and lateral movement in public-sector OA systems.

*Deep dive: `TIER_2_CVE-2024-58406.md`*

___________________________________


# **[CVE-2026-102612 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102612)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

TIER 2 authentication bypass in BACnet/SC building automation stacks impacts Healthcare and Government facility security by allowing unauthenticated mesh access to critical HVAC and life-safety controls.

*Deep dive: `TIER_2_CVE-2026-102612.md`*

___________________________________


# **[CVE-2026-107407 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107407)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Citrix NetScaler ADC/Gateway is a foundational IdAM and secure access platform across Digital Identity, Finance, Government, and Healthcare; SMPP DoS risk impacts regulated messaging gateways.

*Deep dive: `TIER_2_CVE-2026-107407.md`*

___________________________________


# **[CVE-2026-107408 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107408)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Critical unauthenticated DoS in Citrix NetScaler DNS/DoH edge components, directly impacting availability of Finance and Government citizen/banking portals.

*Deep dive: `TIER_2_CVE-2026-107408.md`*

___________________________________


# **[CVE-2026-107409 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107409)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Foundational enterprise load balancer/gateway explicitly underpins Finance, Government, and Healthcare digital infrastructure, though impact is limited to explicitly configured DoH deployments.

*Deep dive: `TIER_2_CVE-2026-107409.md`*

___________________________________


# **[CVE-2026-107411 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107411)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Critical edge infrastructure (Citrix NetScaler) widely deployed across government, finance, and healthcare DPI portals; unauthenticated DoS risk to public-facing access layers.

*Deep dive: `TIER_2_CVE-2026-107411.md`*

___________________________________


# **[CVE-2026-107415 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107415)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Impacts foundational Digital Identity and secure access gateways (Citrix NetScaler) widely deployed in Government and Finance for citizen/customer MFA and SSO, risking critical service disruption.

*Deep dive: `TIER_2_CVE-2026-107415.md`*

___________________________________


# **[CVE-2026-111334 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111334)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Critical unauthenticated DoS in Citrix NetScaler Gateway EPA service, widely deployed as foundational edge infrastructure for Government, Finance, and Digital Identity remote access portals.

*Deep dive: `TIER_2_CVE-2026-111334.md`*

___________________________________


# **[CVE-2026-111337 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111337)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Foundational edge infrastructure (Citrix NetScaler) widely deployed by government and financial institutions for citizen portals and secure access; DoS directly threatens critical public and financial service continuity.

*Deep dive: `TIER_2_CVE-2026-111337.md`*

___________________________________


# **[CVE-2026-111341 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111341)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Impacts client-certificate authentication on widely deployed Citrix NetScaler edge appliances, disrupting remote access and identity services for government, finance, and healthcare sectors.

*Deep dive: `TIER_2_CVE-2026-111341.md`*

___________________________________


# **[CVE-2026-111342 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111342)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Directly impacts LDAP authentication and remote access gateways widely deployed across Digital Identity, Government, Finance, and Healthcare sectors, risking disruption to critical public and regulated services.

*Deep dive: `TIER_2_CVE-2026-111342.md`*

___________________________________


# **[CVE-2026-120864 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120864)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Critical unauthenticated DoS in Citrix NetScaler ADC/Gateway, foundational remote-access infrastructure explicitly tied to Government, Finance, and Healthcare deployments.

*Deep dive: `TIER_2_CVE-2026-120864.md`*

___________________________________


# **[CVE-2026-120865 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120865)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

TIER 2 DoS in Citrix NetScaler ADC/Gateway QUIC handler impacts Government, Finance, and Healthcare sectors reliant on the platform for secure citizen portals, banking gateways, and telemedicine access.

*Deep dive: `TIER_2_CVE-2026-120865.md`*

___________________________________


# **[CVE-2026-120867 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120867)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

TIER 2 unauthenticated DoS in Citrix NetScaler ADC/Gateway threatens availability of internet-facing edge infrastructure critical to Government and Finance digital services.

*Deep dive: `TIER_2_CVE-2026-120867.md`*

___________________________________


# **[CVE-2026-124679 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124679)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

General infrastructure explicitly tied to Finance, Healthcare, and Government edge security, posing authentication bypass risks in regulated API deployments.

*Deep dive: `TIER_2_CVE-2026-124679.md`*

___________________________________


# **[CVE-2026-126091 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126091)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Healthcare sector: unauthenticated exposure of patient PII and OAuth credentials in a cloud dental practice management platform.

*Deep dive: `TIER_2_CVE-2026-126091.md`*

___________________________________


# **[CVE-2026-126429 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126429)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Directly impacts widely deployed open-source Electronic Medical Records (EMR) systems in healthcare, risking PHI and credential theft via patient portals.

*Deep dive: `TIER_2_CVE-2026-126429.md`*

___________________________________


# **[CVE-2026-126454 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126454)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

TIER 2 flaw in OpenEMR EHR enables TOTP brute-force, compromising MFA and risking PHI exposure in healthcare deployments.

*Deep dive: `TIER_2_CVE-2026-126454.md`*

___________________________________


# **[CVE-2026-127090 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127090)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Directly impacts Digital Identity by bypassing SSH public key authentication and breaking account-bound authorization in enterprise remote access and CI/CD environments.

*Deep dive: `TIER_2_CVE-2026-127090.md`*

___________________________________


# **[CVE-2026-127278 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127278)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Directly impacts Digital Identity infrastructure by exposing an unauthenticated authentication bypass in an agent identity registry that manages JWT sessions and OIDC/SAML anchoring.

*Deep dive: `TIER_2_CVE-2026-127278.md`*

___________________________________


# **[CVE-2026-127279 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127279)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Implements national AI agent identity standards (GB/Z 185) for trusted registration and access control, positioning it as foundational digital identity infrastructure for government and regulated AI ecosystems.

*Deep dive: `TIER_2_CVE-2026-127279.md`*

___________________________________


# **[CVE-2026-128041 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-128041)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

TIER 2 stored XSS in OpenMage e-commerce platform impacts the Finance sector by risking payment data, customer accounts, and transaction integrity.

*Deep dive: `TIER_2_CVE-2026-128041.md`*

___________________________________


# **[CVE-2026-82504 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82504)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Unauthenticated RCE in an enterprise IPTV platform explicitly deployed in government and military classified networks.

*Deep dive: `TIER_2_CVE-2026-82504.md`*

___________________________________


# **[CVE-2026-107410 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107410)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

TIER 2 unauthenticated DoS in Citrix NetScaler ADC/Gateway, a foundational public-facing edge proxy critical for regulated and citizen-facing digital services.

*Deep dive: `TIER_2_CVE-2026-107410.md`*

___________________________________


# **[CVE-2026-123975 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-123975)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Pre-auth DoS in Grid Community Toolkit disrupts federated research and government HPC infrastructure, impacting critical scientific and civic data processing.

*Deep dive: `TIER_2_CVE-2026-123975.md`*

___________________________________


# **[CVE-2026-124680 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124680)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Foundational API gateway authorization bypass impacting edge routing and access control in regulated enterprise and public-sector deployments.

*Deep dive: `TIER_2_CVE-2026-124680.md`*

___________________________________


# **[CVE-2026-128049 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-128049)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Finance sector relevance: CSRF in Magento LTS OAuth flow enables persistent API token theft, risking unauthorized access to customer financial data and transaction records.

*Deep dive: `TIER_2_CVE-2026-128049.md`*

___________________________________


# **[CVE-2026-129180 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129180)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Unauthenticated SQLi in a visitor management system commonly deployed in government buildings and public facilities, risking access logs and credential data.

*Deep dive: `TIER_2_CVE-2026-129180.md`*

___________________________________


# **[CVE-2026-62976 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62976)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Impacts building automation infrastructure critical to healthcare facilities and government buildings, risking HVAC and life-safety system availability.

*Deep dive: `TIER_2_CVE-2026-62976.md`*

___________________________________


# **[CVE-2026-97692 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-97692)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

Unauthenticated RCE in BACnet/SC building automation stacks threatens operational continuity and physical security across government, healthcare, and financial facilities.

*Deep dive: `TIER_2_CVE-2026-97692.md`*

___________________________________


# **[CVE-2026-100403 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-100403)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-13

TIER 2 unauthenticated DoS in BACnet/SC hubs disrupts building automation in public and critical facilities, impacting OT infrastructure availability.

*Deep dive: `TIER_2_CVE-2026-100403.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine