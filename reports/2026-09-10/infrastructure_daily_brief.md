# **Infrastructure Daily Brief: 2026-09-10**

**Infrastructure Daily Report TLP:GREEN Alert Id: aad2db5b 2026-09-11 21:47:03**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-89042 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-89043 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-88861 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-88864 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-89086 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-45769 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-81046 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-88007 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-68487 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.i      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.j      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.d      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns                | 1.g      |
| Threats    | Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries          | 1.i      |
| Threats    | Hackers Pose as IT Support to Hijack Microsoft 365 Accounts With Fake Passkey Al | 1.c      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.h      |
| Threats    | Anatomy of a Modern Phishing Campaign                                            | 1.a      |
| Threats    | CVE-2026-87806                                                                   | 1.b      |
| Threats    | CVE-2026-87016                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.i**

Source: ketch Published: 2026-09-10

Microsoft researchers dissect a sophisticated campaign leveraging AI to automate device code generation and OAuth token harvesting. The analysis details how attackers bypass MFA by manipulating the Device Authorization Grant flow, providing infrastructure teams with detection signatures, telemetry indicators, and mitigation strategies for cloud identity services.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.j**

Source: ketch Published: 2026-09-10

Explores how generative AI and autonomous agents are transforming phishing from broad, low-success campaigns into highly targeted, self-optimizing operations. Defenders learn to detect AI-generated content patterns, automate response workflows, and harden identity perimeters against adaptive threat actors that bypass traditional signature-based filters.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.d**

Source: ketch Published: 2026-09-10

Proofpoint tracks the rapid proliferation of device code phishing tools and Phishing-as-a-Service platforms. The report highlights how threat actors exploit corporate validation workflows to bypass multi-factor authentication, offering defenders actionable guidance on monitoring OAuth consent grants, restricting device code flows, and implementing conditional access policies.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.g**

Source: ketch Published: 2026-09-10

Examines how attackers leverage compromised cloud workloads, serverless functions, and CDN networks to host phishing infrastructure that evades traditional blocklists. Infrastructure defenders gain insights into detecting anomalous cloud resource provisioning, securing container registries, and implementing zero-trust network segmentation to disrupt attacker supply chains.

___________________________________


# **[Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html)**

**PIR: 1.i**

Source: ketch Published: 2026-09-10

Documents a widespread OAuth abuse campaign targeting enterprise Microsoft 365 tenants, resulting in persistent token hijacking and lateral movement. Security teams learn to identify suspicious device code requests, revoke compromised tokens, and enforce strict consent policies to mitigate large-scale identity compromise across distributed environments.

___________________________________


# **[Hackers Pose as IT Support to Hijack Microsoft 365 Accounts With Fake Passkey Alerts](https://gbhackers.com/microsoft-365-accounts-hijacked)**

**PIR: 1.c**

Source: ketch Published: 2026-09-10

Details a social engineering campaign where attackers impersonate internal IT helpdesks to trick employees into surrendering passkey credentials. The article outlines the psychological triggers used, provides email header analysis techniques, and recommends endpoint detection rules and user awareness training updates to prevent credential theft and account takeover.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.h**

Source: ketch Published: 2026-09-10

CISA alerts on a zero-click phishing exploit targeting Zimbra email servers, allowing threat actors to inject malicious payloads without user interaction. Infrastructure defenders receive patching priorities, network traffic analysis tips, and isolation procedures to protect legacy email systems and prevent unauthorized access to critical communication channels.

___________________________________


# **[Anatomy of a Modern Phishing Campaign](https://ransomnews.com/anatomy-of-a-modern-phishing-campaign)**

**PIR: 1.a**

Source: ketch Published: 2026-09-10

Breaks down the complete lifecycle of contemporary phishing operations, from initial reconnaissance and domain registration to payload delivery and data exfiltration. The guide equips IT defenders with a structured framework for threat hunting, log correlation, and incident response planning to rapidly contain and eradicate phishing-based intrusions.

___________________________________


# **[CVE-2026-87806](https://nvd.nist.gov/vuln/detail/CVE-2026-87806)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-09

Parse Server versions <= 8.6.87 and >= 9.0.0 < 9.10.1-alpha.7 contain an authentication bypass in the built-in LDAP authentication adapter. The adapter forwarded the client-supplied password to the directory without verifying that a password had been supplied, and treated any non-error response from the directory as proof of authentication. A zero-length credential turns an LDAP simple bind into the unauthenticated authentication mechanism described in RFC 4513 section 5.1.2, which some director

___________________________________


# **[CVE-2026-87016](https://nvd.nist.gov/vuln/detail/CVE-2026-87016)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-09

Open WebUI is an extensible, feature-rich, and user-friendly self-hosted AI platform. From 0.6.41 until 0.11.1, get_user_by_oauth_sub and get_user_by_scim_external_id in backend/open_webui/models/users.py used JSON contains matching that compiled to SQL LIKE substring matching on SQLite. An OAuth subject containing percent or underscore wildcard characters could resolve to a different stored identity, potentially selecting an administrator account and issuing the attacker that account's session;

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-89042 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-89042)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-10

Critical SAML SSO authentication bypass in default Node.js deployments enables arbitrary identity assumption, directly impacting Digital Identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-89042.md`*

___________________________________


# **[CVE-2026-89043 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-89043)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-10

Core Digital Identity risk: bypasses SAML-based SSO and federated authentication, enabling full identity impersonation and privilege escalation in government and finance portals.

*Deep dive: `TIER_2_CVE-2026-89043.md`*

___________________________________


# **[CVE-2026-88861 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-88861)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-10

Direct MFA bypass and session assurance level (AAL) failure in a cloud SaaS platform, undermining core Digital Identity and access control mechanisms.

*Deep dive: `TIER_2_CVE-2026-88861.md`*

___________________________________


# **[CVE-2026-88864 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-88864)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-10

Digital Identity sector: directly poisons SSO enforcement state and bypasses authentication controls in a SaaS CI/CD platform, impacting identity routing and access management.

*Deep dive: `TIER_2_CVE-2026-88864.md`*

___________________________________


# **[CVE-2026-89086 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-89086)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-10

Critical JWT signature bypass in a foundational authentication library directly impacts token-based identity and access management systems used in digital public infrastructure.

*Deep dive: `TIER_2_CVE-2026-89086.md`*

___________________________________


# **[CVE-2026-45769 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-45769)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-10

Core network IDS/IPS engine widely deployed in government and critical infrastructure; DoS blinds perimeter security monitoring.

*Deep dive: `TIER_2_CVE-2026-45769.md`*

___________________________________


# **[CVE-2026-81046 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-81046)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-10

General infrastructure endpoint flaw with unauthenticated RCE, explicitly tied to widespread deployment in government and public sector environments for VDI/RDP access.

*Deep dive: `TIER_2_CVE-2026-81046.md`*

___________________________________


# **[CVE-2026-88007 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-88007)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-10

TIER 2 authentication bypass in Traefik edge proxy impacts foundational networking infrastructure supporting regulated and public digital services.

*Deep dive: `TIER_2_CVE-2026-88007.md`*

___________________________________


# **[CVE-2026-68487 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-68487)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-10

Tier 2 critical path traversal in Plesk hosting panels enables root compromise; impacts general infrastructure widely deployed in public and commercial sectors.

*Deep dive: `TIER_2_CVE-2026-68487.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine