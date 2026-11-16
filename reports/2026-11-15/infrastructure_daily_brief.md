# **Infrastructure Daily Brief: 2026-11-15**

**Infrastructure Daily Report TLP:GREEN Alert Id: fee3a09b 2026-11-16 01:56:45**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-129359 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129349 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129360 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129451 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129483 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129453 (Tier 2)                                                         | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.d.2    |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft  | 1.c.1    |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.e.1    |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.d.3    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.d.1    |
| Threats    | Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...          | 1.d.2    |
| Threats    | Device Code Phishing Drives Identity Takeover Risks                              | 1.d.1    |
| Threats    | Russian hackers can steal government emails without victims clicking a link, cyb | 1.f.1    |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.d.2**

Source: ketch Published: 2026-11-15

This analysis exposes EvilTokens, a sophisticated toolkit enabling device code phishing attacks that bypass traditional MFA. Attackers trick users into entering device codes, granting threat actors direct OAuth tokens without passwords. The article outlines detection signatures, token revocation procedures, and architectural mitigations for identity platforms. Critical for defenders monitoring Azure AD/Entra ID sign-in logs and implementing conditional access policies.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.c.1**

Source: ketch Published: 2026-11-15

Microsoft details the inner workings of Tycoon2FA, a prominent Adversary-in-the-Middle phishing kit that intercepts MFA challenges in real-time. The report explains how reverse proxies capture session cookies and bypass step-up authentication, alongside technical indicators and mitigation strategies. Infrastructure defenders can leverage these insights to harden web application firewalls, deploy FIDO2 security keys, and monitor for anomalous proxy traffic patterns.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.e.1**

Source: ketch Published: 2026-11-15

Microsoft Security researchers dissect the underground ecosystem fueling global phishing campaigns, revealing how threat actors rapidly provision domains, hosting, and proxy networks to evade takedowns. The report details infrastructure-as-a-service models, domain generation algorithms, and defensive strategies for blocking malicious networks at the DNS and proxy layers. Essential for infrastructure teams managing email security gateways and web filtering policies.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.d.3**

Source: ketch Published: 2026-11-15

Researchers uncover a campaign leveraging AI to automate device code phishing at scale, dynamically generating authentication codes and managing victim interactions without human intervention. The attack chain combines LLM-driven social engineering with automated token harvesting, significantly increasing compromise rates. Defenders are advised to implement behavioral analytics for OAuth flows, restrict device code grant usage, and deploy AI-resistant authentication methods like phishing-resista

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.d.1**

Source: ketch Published: 2026-11-15

Proofpoint tracks the rapid proliferation of device code phishing, driven by publicly released toolkits and phishing-as-a-service platforms. The article explains how attackers exploit OAuth device authorization flows to harvest valid tokens, effectively neutralizing password-based MFA. It provides actionable guidance for identity administrators, including monitoring for suspicious device code grants, restricting OAuth app permissions, and educating users on code-entry prompts.

___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.d.2**

Source: ketch Published: 2026-11-15

ReversingLabs documents an active campaign targeting Microsoft 365 environments using polished, business-themed lures combined with the Device Authorization Grant flow. The attack bypasses traditional password theft by directly harvesting OAuth tokens, enabling stealthy account takeover. The report includes campaign infrastructure details, email headers, and mitigation steps for M365 administrators, emphasizing the need for strict OAuth consent policies and user awareness training.

___________________________________


# **[Device Code Phishing Drives Identity Takeover Risks](https://gurucul.com/latest-threats/device-code-phishing-is-an-evolution-in-identity-takeover/)**

**PIR: 1.d.1**

Source: ketch Published: 2026-11-15

Gurucul highlights how device code phishing manipulates corporate validation workflows to compromise high-value employee accounts. The threat bypasses multi-factor authentication by exploiting legitimate OAuth mechanisms, granting attackers persistent access. The analysis recommends infrastructure teams audit delegated permissions, enforce conditional access rules, and monitor for unusual device code authentication patterns to mitigate identity takeover risks across enterprise environments.

___________________________________


# **[Russian hackers can steal government emails without victims clicking a link, cyber agencies warn](https://nextgov.com/cybersecurity/2026/07/russian-hackers-can-steal-government-emails-without-victims-clicking-link-cyber-agencies-warn/414967)**

**PIR: 1.f.1**

Source: ketch Published: 2026-11-15

Cyber agencies warn of Russian threat actors exploiting email client vulnerabilities to steal government credentials without requiring victim interaction. The zero-click technique leverages malicious attachments or rendering flaws to exfiltrate session tokens. Infrastructure teams must prioritize patching email clients, disable auto-preview features, and deploy network segmentation to limit lateral movement following silent compromises.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-129359 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129359)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-15

Hardcoded credential bypass in core 5G/LTE telecom orchestrator directly impacts Government and General Infrastructure sectors by threatening national communications control planes.

*Deep dive: `TIER_2_CVE-2026-129359.md`*

___________________________________


# **[CVE-2026-129349 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129349)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-15

Critical authentication bypass in Apache Shiro's LDAP realm directly undermines Digital Identity verification and access control in enterprise and public-facing services.

*Deep dive: `TIER_2_CVE-2026-129349.md`*

___________________________________


# **[CVE-2026-129360 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129360)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-15

Impacts critical 5G/LTE management planes used by national telecom operators and government-backed connectivity initiatives, risking unauthorized network control and service disruption.

*Deep dive: `TIER_2_CVE-2026-129360.md`*

___________________________________


# **[CVE-2026-129451 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129451)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-15

Critical authenticated path traversal in widely deployed edge routers used by government and SMB networks, risking full device compromise and network perimeter breach.

*Deep dive: `TIER_2_CVE-2026-129451.md`*

___________________________________


# **[CVE-2026-129483 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129483)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-15

Foundational authentication library for email and directory services with broad applicability across government, healthcare, and finance deployments, despite requiring an opt-in SRP configuration.

*Deep dive: `TIER_2_CVE-2026-129483.md`*

___________________________________


# **[CVE-2026-129453 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129453)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-15

TIER 2 authenticated RCE in enterprise perimeter firewall firmware; critical for securing network edges of regulated/public digital services.

*Deep dive: `TIER_2_CVE-2026-129453.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine