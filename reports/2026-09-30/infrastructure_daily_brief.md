# **Infrastructure Daily Brief: 2026-09-30**

**Infrastructure Daily Report TLP:GREEN Alert Id: 5a8f1c67 2026-10-02 03:38:04**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                          | PIR(s)   |
|------------|---------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-102091 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-102101 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-102106 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-102149 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-88920 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-102104 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-102105 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-102115 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-102127 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-102128 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-102143 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-102458 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-103099 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-103547 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-76504 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-86134 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-94052 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-95616 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2024-58387 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-102102 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-103441 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-103442 (Tier 2)                                                        | 3.k      |
| Cyber News | CVE-2026-89238 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2023-54403 (Tier 2)                                                         | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing               | 1.g      |
| Threats    | Passkey-themed social engineering leads to identity and cloud compromise        | 1.g      |
| Threats    | Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI | 1.j.3    |
| Threats    | AI-Generated Lures Behind Microsoft Cloud Account Takeovers                     | 1.f      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                 | 1.h      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                       | 1.d      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations        | 1.f      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA     | 1.i      |
| Threats    | CVE-2026-97274                                                                  | 1.b      |
| Threats    | CVE-2026-76142                                                                  | 1.b      |
| Threats    | CVE-2026-103651                                                                 | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.g**

Source: ketch Published: 2026-09-30

Microsoft researchers dissect the EvilTokens infrastructure, revealing how threat actors automate device code phishing at scale. By exploiting OAuth 2.0 device authorization flows, attackers harvest long-lived tokens that bypass MFA and persist across sessions. The report details detection signatures, token revocation procedures, and architectural mitigations for identity platforms. Critical for SecOps teams managing Azure AD and hybrid cloud environments.

___________________________________


# **[Passkey-themed social engineering leads to identity and cloud compromise](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/)**

**PIR: 1.g**

Source: ketch Published: 2026-09-30

Attackers are increasingly leveraging passkey authentication prompts to bypass traditional MFA defenses. This campaign uses highly targeted social engineering to trick users into approving legitimate-looking passkey requests, granting threat actors direct access to cloud environments and identity providers. Defenders must monitor for anomalous passkey approval patterns, enforce conditional access policies, and educate users on recognizing spoofed authentication prompts.

___________________________________


# **[Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI](https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing)**

**PIR: 1.j.3**

Source: ketch Published: 2026-09-30

Threat intelligence reveals that a Midnight Blizzard-associated group has integrated AI automation into device code phishing operations. The actor uses machine learning to optimize landing page deployment, credential harvesting timing, and victim targeting. Infrastructure defenders should prioritize monitoring for automated OAuth consent requests, implement token lifetime restrictions, and correlate identity logs with known APT TTPs.

___________________________________


# **[AI-Generated Lures Behind Microsoft Cloud Account Takeovers](https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s)**

**PIR: 1.f**

Source: ketch Published: 2026-09-30

The Cloud Security Alliance analyzes a surge in account takeovers driven by generative AI-crafted phishing lures. These campaigns dynamically adapt language, branding, and urgency cues to evade email security filters and maximize click-through rates. The research highlights the limitations of traditional URL reputation checks and recommends AI-aware content inspection, behavioral analytics, and zero-trust identity validation for cloud workloads.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.h**

Source: ketch Published: 2026-09-30

CISA alerts on a zero-click phishing campaign targeting Zimbra email servers, exploited by the Russian-linked Laundry Bear group. The attack leverages a server-side vulnerability to deliver malicious payloads without user interaction, bypassing traditional email security gateways. Infrastructure teams must prioritize immediate patching, implement network segmentation for mail servers, and monitor for lateral movement indicators post-exploitation.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.d**

Source: ketch Published: 2026-09-30

Proofpoint outlines how device code phishing has matured from opportunistic attacks into a systematic identity takeover methodology. By redirecting users to malicious OAuth consent pages, attackers capture authorization codes that exchange for persistent access tokens. The article provides network-level indicators, proxy blocking strategies, and user training frameworks to mitigate this growing vector in enterprise environments.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.f**

Source: ketch Published: 2026-09-30

This analysis tracks the shift from bulk phishing campaigns to fully autonomous, AI-driven operations. Modern threat actors deploy LLMs to generate context-aware lures, manage infrastructure provisioning, and adapt to security controls in real time. Defenders must transition from signature-based detection to behavioral anomaly monitoring, implement strict email authentication, and prepare incident response playbooks for AI-accelerated breaches.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.i**

Source: ketch Published: 2026-09-30

CYFIRMA documents how adversaries leverage compromised cloud instances, serverless functions, and CDN networks to host phishing infrastructure. By blending malicious traffic with legitimate cloud services, attackers evade traditional perimeter defenses and IP blocklists. The report recommends cloud workload protection, DNS monitoring, and egress filtering to disrupt infrastructure abuse and protect identity endpoints.

___________________________________


# **[CVE-2026-97274](https://nvd.nist.gov/vuln/detail/CVE-2026-97274)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-30

Unauthenticated Bypass Vulnerability in OAuth Single Sign On – SSO (OAuth Client) <= 7.1.2 versions.

___________________________________


# **[CVE-2026-76142](https://nvd.nist.gov/vuln/detail/CVE-2026-76142)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-01

Insufficient authentication and access control on the internal-only IPC SOAP endpoint of the Genian NAC/ZTNA policy server allows an unauthenticated attacker to invoke internal functions

___________________________________


# **[CVE-2026-103651](https://nvd.nist.gov/vuln/detail/CVE-2026-103651)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-01

MISP contains a vulnerability in its one-time password (OTP) authentication flow that allows replay of a consumed HOTP (paper) token and rewinding of the token counter.

The HOTP verification logic compared the submitted token against a counter value that was cached in the user's session at the time the password was entered, rather than against the authoritative counter stored in the database. Because the session-cached counter is not updated after a token is successfully consumed, an attacker w

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-102091 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102091)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Unauthenticated SSRF in Kiteworks Secure Data Forms, a platform widely deployed across government, healthcare, and finance for regulated, internet-facing data collection.

*Deep dive: `TIER_2_CVE-2026-102091.md`*

___________________________________


# **[CVE-2026-102101 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102101)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

RCE in Kiteworks Core PDN appliance, widely deployed across Government, Healthcare, and Finance for secure MFT and cross-organizational data exchange.

*Deep dive: `TIER_2_CVE-2026-102101.md`*

___________________________________


# **[CVE-2026-102106 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102106)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Critical admin auth bypass in Kiteworks EPG, widely deployed in government and regulated sectors for CUI/PHI email protection.

*Deep dive: `TIER_2_CVE-2026-102106.md`*

___________________________________


# **[CVE-2026-102149 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102149)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Strong Digital Identity and Government relevance due to certificate-based authentication bypass impacting secure email gateways widely deployed in defense and public sector.

*Deep dive: `TIER_2_CVE-2026-102149.md`*

___________________________________


# **[CVE-2026-88920 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-88920)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Critical authentication bypass in Apache WSS4J undermines SAML-based federated identity trust chains, directly impacting Digital Identity, Finance, and Government B2B/API integrations.

*Deep dive: `TIER_2_CVE-2026-88920.md`*

___________________________________


# **[CVE-2026-102104 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102104)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Government / General Infrastructure: Unauthenticated SSRF in Kiteworks Email Protection Gateway, widely deployed across government agencies and defense contractors for secure communications.

*Deep dive: `TIER_2_CVE-2026-102104.md`*

___________________________________


# **[CVE-2026-102105 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102105)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Unauthenticated SSRF in a perimeter email gateway widely deployed by Government and Healthcare sectors to protect CUI/PHI, enabling internal network pivoting and cloud credential theft.

*Deep dive: `TIER_2_CVE-2026-102105.md`*

___________________________________


# **[CVE-2026-102115 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102115)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Unauthenticated password reset bypass in Kiteworks Core enables account takeover, directly impacting Digital Identity and Government/regulated enterprise file-sharing infrastructure.

*Deep dive: `TIER_2_CVE-2026-102115.md`*

___________________________________


# **[CVE-2026-102127 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102127)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Government sector relevance: Kiteworks Email Protection Gateway is widely deployed by US federal agencies and defense contractors; XXE flaw risks exfiltration of credentials and cryptographic keys.

*Deep dive: `TIER_2_CVE-2026-102127.md`*

___________________________________


# **[CVE-2026-102128 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102128)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Unauthenticated identity-verification bypass in Kiteworks EPG enables remote account takeover, directly impacting secure Government communications infrastructure.

*Deep dive: `TIER_2_CVE-2026-102128.md`*

___________________________________


# **[CVE-2026-102143 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102143)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Unauthenticated arbitrary file write on Kiteworks Email Protection Gateway, widely deployed in US government and defense for secure email infrastructure.

*Deep dive: `TIER_2_CVE-2026-102143.md`*

___________________________________


# **[CVE-2026-102458 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102458)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Plaintext credential exposure in Digiwin EasyFlow BPM platform, widely deployed by Taiwanese government agencies and regional financial institutions for public service and compliance workflows.

*Deep dive: `TIER_2_CVE-2026-102458.md`*

___________________________________


# **[CVE-2026-103099 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103099)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Unauthenticated remote DoS on internet-facing enterprise video conferencing nodes widely deployed across government, healthcare, and finance for critical remote operations.

*Deep dive: `TIER_2_CVE-2026-103099.md`*

___________________________________


# **[CVE-2026-103547 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103547)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Core LDAP directory service (ldapd) race condition enables remote authentication bypass and identity hijacking, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-103547.md`*

___________________________________


# **[CVE-2026-76504 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76504)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Foundational SD-WAN control plane vulnerability explicitly tied to Government and regulated sector networks, with active wild exploitation and CISA KEV listing.

*Deep dive: `TIER_2_CVE-2026-76504.md`*

___________________________________


# **[CVE-2026-86134 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86134)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Unauthenticated remote DoS on WatchGuard Fireware OS management interface poses systemic availability risk to Government, Finance, and Healthcare network perimeters.

*Deep dive: `TIER_2_CVE-2026-86134.md`*

___________________________________


# **[CVE-2026-94052 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-94052)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Critical authentication bypass in Apache MINA SSHD's LDAP module impacts Digital Identity and enterprise access control for bastion/CI-CD infrastructure.

*Deep dive: `TIER_2_CVE-2026-94052.md`*

___________________________________


# **[CVE-2026-95616 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-95616)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Foundational Java WS-Security library extensively deployed across government, healthcare, and finance for secure SOAP integrations; unauthenticated DoS directly threatens regulated API availability.

*Deep dive: `TIER_2_CVE-2026-95616.md`*

___________________________________


# **[CVE-2024-58387 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2024-58387)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Unauthenticated file read in Inspur HCM Cloud, widely deployed in Chinese government and state-owned enterprises, enabling credential theft and lateral movement.

*Deep dive: `TIER_2_CVE-2024-58387.md`*

___________________________________


# **[CVE-2026-102102 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102102)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

TIER 2 unauthenticated SSRF in a widely deployed enterprise email security gateway, explicitly noted as impacting Government, Healthcare, and Finance perimeter defenses.

*Deep dive: `TIER_2_CVE-2026-102102.md`*

___________________________________


# **[CVE-2026-103441 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103441)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Government sector: unauthenticated RCE in MediaWiki/Wikibase impacts public-facing civic knowledge bases and structured data platforms deployed by government entities.

*Deep dive: `TIER_2_CVE-2026-103441.md`*

___________________________________


# **[CVE-2026-103442 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103442)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Affects centralized authentication and session management in MediaWiki deployments used by public-sector and educational knowledge bases, impacting General Infrastructure and Digital Identity sectors.

*Deep dive: `TIER_2_CVE-2026-103442.md`*

___________________________________


# **[CVE-2026-89238 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-89238)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Foundational WS-Security library for enterprise SOAP APIs, explicitly noted for impact on government and finance B2B integrations relying on compliance-grade security policies.

*Deep dive: `TIER_2_CVE-2026-89238.md`*

___________________________________


# **[CVE-2023-54403 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2023-54403)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-30

Tier 2 enterprise CRM flaw with active exploitation; report explicitly ties deployment to government and finance sectors, highlighting credential theft risks in regulated environments.

*Deep dive: `TIER_2_CVE-2023-54403.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine