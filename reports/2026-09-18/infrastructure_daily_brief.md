# **Infrastructure Daily Brief: 2026-09-18**

**Infrastructure Daily Report TLP:GREEN Alert Id: b1a45da3 2026-09-21 08:41:30**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-87743 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93568 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93569 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-75031 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-75878 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-81626 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-81657 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82967 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84108 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-89058 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93558 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93564 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93567 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-13673 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-80441 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-84075 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-92701 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93468 (Tier 2)                                                          | 3.k      |
| Threats    | GhostCode Abuses Microsoft Device Codes to Steal M365 Tokens and Register Rogue  | 1.d      |
| Threats    | GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Secon | 1.d      |
| Threats    | Microsoft 365: Block Device Code Flow Against GhostCode                          | 1.g      |
| Threats    | GhostCode attackers abuse device codes to take over Microsoft 365 accounts       | 1.d      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.a      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations         | 1.c      |
| Threats    | Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncove | 1.b      |
| Threats    | Operation HookedWing: 4 Years, 500 Organizations, 2,000 Credentials              | 1.e      |
| Threats    | CVE-2026-88952                                                                   | 1.b      |
| Threats    | CVE-2026-14850                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[GhostCode Abuses Microsoft Device Codes to Steal M365 Tokens and Register Rogue Devices](https://cyberpress.org/ghostcode-m365-device-code)**

**PIR: 1.d**

Source: ketch Published: 2026-09-18

Analyzes how threat actors exploit the device code flow to steal Microsoft 365 tokens and register rogue devices, effectively bypassing traditional MFA. Infrastructure defenders must monitor Entra ID device enrollment logs, restrict device code flows, and enforce conditional access policies to prevent persistent unauthorized access.

___________________________________


# **[GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds](https://cybersecuritynews.com/ghostcode-phishing-kit/amp)**

**PIR: 1.d**

Source: ketch Published: 2026-09-18

Details a sophisticated phishing kit that intercepts device codes to hijack accounts in under two minutes. Highlights the critical need for infrastructure teams to implement real-time authentication monitoring, deploy phishing-resistant MFA, and configure automated alerts for anomalous device registration events.

___________________________________


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973)**

**PIR: 1.g**

Source: ketch Published: 2026-09-18

Provides actionable administrative guidance for disabling or restricting the device code flow within Microsoft 365 and Entra ID. Essential reading for infrastructure defenders seeking to harden authentication boundaries, mitigate token theft, and enforce stricter identity governance across enterprise environments.

___________________________________


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.d**

Source: ketch Published: 2026-09-18

Examines operational tactics used to compromise M365 accounts via device code abuse. Recommends infrastructure defenders implement token lifetime restrictions, monitor for unauthorized device registrations, and accelerate migration to passwordless authentication to reduce attack surface.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.a**

Source: ketch Published: 2026-09-18

Analyzes how attackers leverage serverless functions, container registries, and cloud storage to host resilient phishing infrastructure. Defenders should audit cloud resource permissions, implement strict egress filtering, and monitor for anomalous cloud-native service usage to disrupt campaign hosting.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.c**

Source: ketch Published: 2026-09-18

Covers the shift from manual campaigns to AI-driven, autonomous phishing operations that adapt in real-time. Infrastructure defenders should prioritize email gateway AI detection, user behavior analytics, and automated incident response playbooks to counter increased scale and sophistication.

___________________________________


# **[Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncovers a Massive Canada-First Banking Operation + Video - UNDERCODE NEWS](https://undercodenews.com/fast-flux-phishing-turns-the-internet-into-a-moving-target-as-silent-push-uncovers-a-massive-canada-first-banking-operation-video)**

**PIR: 1.b**

Source: ketch Published: 2026-09-18

Explores how fast-flux DNS techniques make phishing domains highly resilient to takedowns. Network and infrastructure teams must deploy DNS threat intelligence, implement sinkholing strategies, and monitor for rapid IP rotation patterns to effectively block malicious traffic at the perimeter.

___________________________________


# **[Operation HookedWing: 4 Years, 500 Organizations, 2,000 Credentials](https://www.gblock.app/articles/operation-hookedwing-four-year-phishing-500-orgs-may-2026)**

**PIR: 1.e**

Source: ketch Published: 2026-09-18

Documents a persistent four-year campaign harvesting credentials across hundreds of organizations. Highlights the importance of continuous credential monitoring, passwordless migration, and infrastructure segmentation to limit lateral movement and contain breaches post-initial compromise.

___________________________________


# **[CVE-2026-88952](https://nvd.nist.gov/vuln/detail/CVE-2026-88952)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-17

Improper Authentication vulnerability in team-alembic AshAuthentication allows an attacker to be signed in as another user by linking an OAuth2 identity to an account that is not theirs.

AshAuthentication.Strategy.OAuth2.UserResolver.resolve/3 matches an existing account using the register action's upsert_identity keys, then gates linking the incoming provider identity to it on email_trusted?/2, which reads only the provider's email_verified boolean and never compares the provider's email value

___________________________________


# **[CVE-2026-14850](https://nvd.nist.gov/vuln/detail/CVE-2026-14850)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-17

The password reset funcionality is vulnerable to unauthorized account modification due to improper validation of the user_id parameter. An attacker can manipulate this predictable numeric identifier to reset passwords for arbitrary users without proving account ownership.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-87743 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-87743)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Direct authorization bypass in Keycloak and Quarkus-based IAM services enables unauthenticated access to identity data and admin interfaces, impacting Digital Identity and cloud-native infrastructure.

*Deep dive: `TIER_2_CVE-2026-87743.md`*

___________________________________


# **[CVE-2026-93568 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93568)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Directly impacts Red Hat Keycloak and SSO (Digital Identity sector) by enabling authorization/routing bypass in public-facing IdAM gateways.

*Deep dive: `TIER_2_CVE-2026-93568.md`*

___________________________________


# **[CVE-2026-93569 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93569)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Directly impacts core IdAM platforms (Keycloak, Red Hat SSO) by enabling authentication/authorization bypass and tenant isolation breaks via HTTP/1-to-HTTP/2 authority confusion.

*Deep dive: `TIER_2_CVE-2026-93569.md`*

___________________________________


# **[CVE-2026-75031 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-75031)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Unauthenticated RCE in a payment-adjacent e-commerce framework directly threatens financial transaction infrastructure and digital commerce services.

*Deep dive: `TIER_2_CVE-2026-75031.md`*

___________________________________


# **[CVE-2026-75878 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-75878)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Critical SSO authentication bypass on internet-facing B2B file transfer gateways widely deployed in Finance, Healthcare, and Government for secure data exchange.

*Deep dive: `TIER_2_CVE-2026-75878.md`*

___________________________________


# **[CVE-2026-81626 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-81626)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Unauthenticated SQLi in IBM Guardium, a foundational data protection and compliance appliance critical to regulated Finance, Healthcare, and Government environments.

*Deep dive: `TIER_2_CVE-2026-81626.md`*

___________________________________


# **[CVE-2026-81657 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-81657)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Critical unauthenticated RCE in IBM Guardium, a foundational database security appliance explicitly deployed across Finance, Healthcare, and Government sectors for regulatory compliance.

*Deep dive: `TIER_2_CVE-2026-81657.md`*

___________________________________


# **[CVE-2026-82967 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82967)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Critical database security and compliance monitoring appliance widely deployed across Finance, Healthcare, and Government sectors to enforce PCI-DSS, HIPAA, and GDPR audit controls.

*Deep dive: `TIER_2_CVE-2026-82967.md`*

___________________________________


# **[CVE-2026-84108 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84108)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

High-impact RCE in IBM Guardium, a foundational compliance and data protection appliance widely deployed across Finance, Healthcare, and Government sectors to secure regulated databases and citizen/patient records.

*Deep dive: `TIER_2_CVE-2026-84108.md`*

___________________________________


# **[CVE-2026-89058 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-89058)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Directly impacts core Digital Identity stacks (Keycloak, SSO) and enterprise backend infrastructure, risking authenticated session and token leakage via CORS misconfiguration.

*Deep dive: `TIER_2_CVE-2026-89058.md`*

___________________________________


# **[CVE-2026-93558 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93558)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Impacts core Digital Identity providers (Keycloak/SSO) and foundational Java frameworks widely deployed in regulated government, finance, and healthcare backend services.

*Deep dive: `TIER_2_CVE-2026-93558.md`*

___________________________________


# **[CVE-2026-93564 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93564)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

DoS vulnerability in Netty HAProxy decoder impacts core Digital Identity platforms (Keycloak, Red Hat SSO), risking disruption to authentication, SSO, and token issuance services.

*Deep dive: `TIER_2_CVE-2026-93564.md`*

___________________________________


# **[CVE-2026-93567 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93567)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Digital Identity: Impacts Red Hat Keycloak and Single Sign-On IdAM gateways, enabling HTTP/2 CONNECT tunneling that bypasses egress policies and undermines identity federation controls.

*Deep dive: `TIER_2_CVE-2026-93567.md`*

___________________________________


# **[CVE-2026-13673 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-13673)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

TIER 2 LDAP API permission flaw in widely deployed Synology NAS infrastructure, impacting directory services and data integrity in regulated/public sector storage environments.

*Deep dive: `TIER_2_CVE-2026-13673.md`*

___________________________________


# **[CVE-2026-80441 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80441)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

General infrastructure critical to regulated sector compliance (Finance, Healthcare, Government); unauthenticated SQLi compromises audit integrity and data confidentiality.

*Deep dive: `TIER_2_CVE-2026-80441.md`*

___________________________________


# **[CVE-2026-84075 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-84075)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

General infrastructure (database security appliance) explicitly tied to regulated Finance, Healthcare, and Government deployments; unauthenticated bypass enables lateral movement and policy tampering.

*Deep dive: `TIER_2_CVE-2026-84075.md`*

___________________________________


# **[CVE-2026-92701 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-92701)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

Affects foundational confidential computing/TEE attestation infrastructure explicitly noted to underpin regulated Healthcare, Finance, and Government data-sharing initiatives.

*Deep dive: `TIER_2_CVE-2026-92701.md`*

___________________________________


# **[CVE-2026-93468 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93468)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-18

TIER 2 unauthenticated file read in HGiga OAKlouds collaboration portal widely deployed across Taiwanese government and public-sector organizations for internal policy dissemination.

*Deep dive: `TIER_2_CVE-2026-93468.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine