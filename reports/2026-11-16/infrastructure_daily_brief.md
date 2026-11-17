# **Infrastructure Daily Brief: 2026-11-16**

**Infrastructure Daily Report TLP:GREEN Alert Id: 7d25cf30 2026-11-17 08:02:42**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-130070 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-104840 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-127218 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-129295 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-130066 (Tier 2)                                                         | 3.k      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale              | 1.b      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.e      |
| Threats    | High volume phishing campaign uses Microsoft 365 outage lures to target multiple | 1.d      |
| Threats    | The Hidden Relay: Inside a Device Code Phishing Kit That Never Shows the Code    | 1.g      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.c      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.f      |
| Threats    | Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM | 1.b      |
| Threats    | CVE-2026-129483                                                                  | 1.b      |
| Threats    | CVE-2026-129349                                                                  | 1.b      |
| Threats    | CVE-2026-74762                                                                   | 1.b      |
| Threats    | CVE-2026-129347                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime)**

**PIR: 1.a**

Source: ketch Published: 2026-11-16

Analyzes the underlying hosting, domain registration, and monetization layers supporting modern phishing operations. Provides actionable intelligence for infrastructure defenders to map threat actor supply chains, implement proactive DNS sinkholing, and disrupt attacker infrastructure before campaigns scale.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale)**

**PIR: 1.b**

Source: ketch Published: 2026-11-16

Dissects a commercial Adversary-in-the-Middle kit that proxies authentication sessions to steal valid MFA tokens. Demonstrates how traditional password-plus-OTP is bypassed and underscores the urgent shift toward phishing-resistant MFA standards like FIDO2 and certificate-based authentication.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.e**

Source: ketch Published: 2026-11-16

Leverages generative AI to dynamically generate convincing login prompts and device code flows. Bypasses traditional URL filtering and requires behavioral analytics to detect automated consent grants, highlighting gaps in static web proxy defenses and the need for adaptive identity monitoring.

___________________________________


# **[High volume phishing campaign uses Microsoft 365 outage lures to target multiple industry sectors](https://microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2)**

**PIR: 1.d**

Source: ketch Published: 2026-11-16

Exploits real-time service disruptions to trick users into credential submission. Highlights the critical need for rapid, authoritative incident communication channels and conditional access policies that detect anomalous login patterns and impossible travel during documented outages.

___________________________________


# **[The Hidden Relay: Inside a Device Code Phishing Kit That Never Shows the Code](https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code)**

**PIR: 1.g**

Source: ketch Published: 2026-11-16

Introduces a novel kit that intercepts device code flows without displaying the code to the victim, using background relays. Challenges traditional detection methods and requires deep packet inspection, API gateway monitoring, and strict OAuth scope limitations to prevent silent token theft.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.c**

Source: ketch Published: 2026-11-16

Explains how attackers abuse OAuth device authorization flows to capture tokens without passwords. Critical for identity architects to restrict unnecessary device code grants, monitor for rapid token validation patterns, and implement step-up authentication for sensitive administrative actions.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.f**

Source: ketch Published: 2026-11-16

Details how attackers pivot from credential harvesting to direct token theft via device code abuse. Emphasizes the need to disable unnecessary OAuth grants, implement short token lifetimes, and deploy identity threat detection platforms that flag anomalous device code validation sequences.

___________________________________


# **[Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise](https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise)**

**PIR: 1.b**

Source: ketch Published: 2026-11-16

Analyzes a multi-stage campaign using fake compliance documents to deliver AiTM proxies. Shows how social engineering combines with technical token theft to compromise enterprise accounts, emphasizing the need for email authentication hardening and user training on document verification.

___________________________________


# **[CVE-2026-129483](https://nvd.nist.gov/vuln/detail/CVE-2026-129483)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-15

Cyrus SASL through 2.1.28 contains an authentication bypass vulnerability in the SRP server mechanism because srp_server_mech_step2 does not reject client public values A that are multiples of N. Unauthenticated network clients can send A equal to N to force a zero shared secret, authenticating as any existing user without the password and learning session keys.

___________________________________


# **[CVE-2026-129349](https://nvd.nist.gov/vuln/detail/CVE-2026-129349)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-15

When authentication caching is enabled on DefaultLdapRealm, after a user logs in successfully once, subsequent logins for that user succeed with any password.
A cached authentication skips the LDAP bind, and the AllowAllCredentialsMatcher installed by default in DefaultLdapRealm accepts any credentials, allowing an attacker who knows a valid username to authenticate as that user.
This issue affects all Apache Shiro versions through 3.0.0, only when using DefaultLdapRealm (or JndiLdapRealm) with 

___________________________________


# **[CVE-2026-74762](https://nvd.nist.gov/vuln/detail/CVE-2026-74762)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-16

Apache Shiro is vulnerable to session fixation when a user is authenticated via the "Remember me" functionality. In affected versions, when a subject is restored from a "Remember me" cookie, the existing session is not invalidated, nor is a new session created with a new ID.
Additionally, session IDs were accepted from the request URL even when session ID URL rewriting was disabled.
This issue affects all Apache Shiro versions through 3.0.0, only when RememberMe functionality is enabled.

Mitiga

___________________________________


# **[CVE-2026-129347](https://nvd.nist.gov/vuln/detail/CVE-2026-129347)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-16

`DefaultPasswordService` and `SimpleCredentialsMatcher` could treat an empty stored credential as a match for an empty submitted password.
This issue affects all Apache Shiro versions through 3.0.1, only when accounts with an empty stored credential exist.

Mitigation: Upgrade to version 3.0.2 or later, which fixes the issue.
Alternatively, avoid storing empty credentials, and reject empty passwords in the application.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-130070 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-130070)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-16

Critical unauthenticated authentication bypass and OAuth token theft in a Frappe/ERPNext extension, directly impacting Digital Identity pipelines and public service account security.

*Deep dive: `TIER_2_CVE-2026-130070.md`*

___________________________________


# **[CVE-2026-104840 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104840)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-16

Critical for Government/CERT infrastructure; unauthenticated brute-force on OpenCTI threatens national threat intelligence platforms and defence agency data.

*Deep dive: `TIER_2_CVE-2026-104840.md`*

___________________________________


# **[CVE-2026-127218 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127218)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-16

Unauthenticated DoS in Axigen Mail Server, a foundational email gateway explicitly tied to government, finance, and healthcare communications infrastructure.

*Deep dive: `TIER_2_CVE-2026-127218.md`*

___________________________________


# **[CVE-2026-129295 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129295)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-16

General infrastructure email parsing library underpins critical ticketing and quarantine operations across Finance, Government, and Healthcare sectors.

*Deep dive: `TIER_2_CVE-2026-129295.md`*

___________________________________


# **[CVE-2026-130066 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-130066)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-16

Tier 2 authenticated SQLi in widely deployed enterprise groupware (SOGo) that leaks password hashes, impacting public sector, healthcare, and finance deployments.

*Deep dive: `TIER_2_CVE-2026-130066.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine