# **Infrastructure Daily Brief: 2026-10-14**

**Infrastructure Daily Report TLP:GREEN Alert Id: 4a30c2e5 2026-10-18 15:46:00**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-111882 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111911 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111880 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111924 (Tier 2)                                                         | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.b.4    |
| Threats    | Microsoft Disrupts YAM Store Network Behind 1 Billion Phishing Scams and M365 De | 1.b.2    |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.d.2    |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.c.1    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.b.1    |
| Threats    | Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vish | 1.e.3    |
| Threats    | Access granted: phishing with device code authorization for account takeover | P | 1.b.3    |
| Threats    | n8n Weaponized for Phishing and Device Fingerprinting                            | 1.d.1    |
| Threats    | CVE-2026-93909                                                                   | 1.b      |
| Threats    | CVE-2026-77910                                                                   | 1.b      |
| Threats    | CVE-2026-83928                                                                   | 1.b      |
| Threats    | CVE-2026-70580                                                                   | 1.b      |
| Threats    | CVE-2026-69802                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.b.4**

Source: ketch Published: 2026-10-14

This technical deep dive examines EvilTokens, a sophisticated framework enabling persistent device-code phishing attacks that bypass MFA and conditional access controls. Attackers harvest long-lived tokens by tricking users into authorizing malicious apps, granting them seamless access to M365 and Azure resources. Infrastructure teams must audit OAuth app permissions, revoke suspicious device codes, and implement token lifetime restrictions to neutralize this identity takeover vector.

___________________________________


# **[Microsoft Disrupts YAM Store Network Behind 1 Billion Phishing Scams and M365 Device-Code Attacks](https://windowsforum.com/news/microsoft-disrupts-yam-store-network-behind-1-billion-phishing-scams-and-m365-device-code-attacks.448313/post-1012947)**

**PIR: 1.b.2**

Source: ketch Published: 2026-10-14

Microsoft’s coordinated takedown of the YAM Store network dismantled a massive infrastructure responsible for over one billion phishing attempts and widespread M365 device-code attacks. The campaign exploited compromised legitimate services to host credential-harvesting pages and bypass email security filters. Defenders should review M365 audit logs for suspicious device-code authorizations, enforce conditional access policies, and monitor for traffic to known YAM Store domains to prevent identi

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d.2**

Source: ketch Published: 2026-10-14

Threat actors are integrating generative AI to automate device-code phishing campaigns, dynamically generating realistic login pages and contextual lures that adapt to victim behavior. The AI-driven infrastructure scales attacks rapidly while evading signature-based detection. Defenders should deploy AI-aware web filtering, monitor for anomalous OAuth consent requests, and enforce strict conditional access rules to block automated identity harvesting attempts.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.c.1**

Source: ketch Published: 2026-10-14

Threat actors increasingly leverage ephemeral cloud resources, serverless functions, and containerized environments to host phishing infrastructure, evading traditional IP-based blocklists. This report details how attackers abuse cloud-native APIs to dynamically provision phishing domains and redirect traffic, complicating takedown efforts. Infrastructure defenders must implement cloud workload protection platforms, enforce strict IAM policies, and monitor for anomalous resource provisioning pat

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b.1**

Source: ketch Published: 2026-10-14

Device code phishing has emerged as a primary vector for identity takeover, allowing attackers to bypass traditional password and MFA defenses by exploiting OAuth 2.0 authorization flows. This analysis outlines the attack lifecycle, detection signatures, and mitigation strategies for enterprise environments. IT infrastructure teams must prioritize monitoring of device code endpoints, implement just-in-time access controls, and educate users on recognizing authorization prompts.

___________________________________


# **[Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM](https://intel.threadlinqs.com/threat/TL-2026-3778)**

**PIR: 1.e.3**

Source: ketch Published: 2026-10-14

Attackers are exploiting Microsoft Teams’ external chat and screen-sharing features to impersonate IT helpdesk personnel, tricking users into granting remote access via RMM tools. This vishing and social engineering campaign bypasses traditional email filters by operating entirely within collaboration platforms. Defenders should disable external Teams messaging where possible, enforce multi-factor authentication for RMM access, and train staff to verify helpdesk requests through out-of-band chan

___________________________________


# **[Access granted: phishing with device code authorization for account takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.b.3**

Source: ketch Published: 2026-10-14

This foundational report details how attackers leverage device code authorization flows to harvest valid access tokens, effectively bypassing multi-factor authentication. By directing users to malicious consent pages, threat actors gain persistent access to cloud identities. Defenders should audit Azure AD sign-in logs for device code flows, restrict third-party app registrations, and deploy identity protection solutions to detect and block anomalous authorization requests.

___________________________________


# **[n8n Weaponized for Phishing and Device Fingerprinting](https://labs.cloudsecurityalliance.org/research/csa-research-note-n8n-ai-workflow-phishing-20260416-csa-styl)**

**PIR: 1.d.1**

Source: ketch Published: 2026-10-14

Cybercriminals are repurposing the open-source workflow automation tool n8n to orchestrate phishing campaigns and collect detailed device fingerprints. By chaining n8n workflows with browser fingerprinting scripts, attackers tailor phishing payloads to specific victim environments, increasing success rates. IT teams must monitor for unauthorized n8n deployments, restrict outbound API calls from automation servers, and deploy browser fingerprinting detection in web proxies to disrupt these adapti

___________________________________


# **[CVE-2026-93909](https://nvd.nist.gov/vuln/detail/CVE-2026-93909)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-13

IBM WebSphere Application Server - Liberty 17.0.0.3 through 26.0.0.10 is vulnerable by an authentication bypass vulnerability when samlWeb-2.0 feature is enabled.

___________________________________


# **[CVE-2026-77910](https://nvd.nist.gov/vuln/detail/CVE-2026-77910)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-13

Incorrect authorization in Microsoft Exchange Server allows an authorized attacker to elevate privileges over a network.

___________________________________


# **[CVE-2026-83928](https://nvd.nist.gov/vuln/detail/CVE-2026-83928)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-13

Out-of-bounds write in Windows Local Security Authority Subsystem Service (LSASS) allows an unauthorized attacker to execute code over a network.

___________________________________


# **[CVE-2026-70580](https://nvd.nist.gov/vuln/detail/CVE-2026-70580)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-13

Missing authentication for critical function in Windows Credential Guard allows an authorized attacker to perform spoofing locally.

___________________________________


# **[CVE-2026-69802](https://nvd.nist.gov/vuln/detail/CVE-2026-69802)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-13

Weak authentication in Network Device Enrollment Service (NDES) allows an unauthorized attacker to execute code over a network.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-111882 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111882)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-14

Directly impacts Digital Identity by bypassing TOTP 2FA in OIDC/SSO flows (Keycloak, Entra ID), risking account takeover in government and enterprise support portals.

*Deep dive: `TIER_2_CVE-2026-111882.md`*

___________________________________


# **[CVE-2026-111911 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111911)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-14

Directly compromises WebAuthn passkey registration and bypasses TOTP 2FA in public-facing knowledge bases, impacting Digital Identity and access controls for regulated customer portals.

*Deep dive: `TIER_2_CVE-2026-111911.md`*

___________________________________


# **[CVE-2026-111880 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111880)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-14

General infrastructure (FreeRDP) widely deployed in government and healthcare for remote access/VDI, impacting cross-sector availability.

*Deep dive: `TIER_2_CVE-2026-111880.md`*

___________________________________


# **[CVE-2026-111924 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111924)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-14

General infrastructure MDM platform deployed in government and healthcare; unauthenticated DoS halts endpoint management.

*Deep dive: `TIER_2_CVE-2026-111924.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine