# **Infrastructure Daily Brief: 2026-11-22**

**Infrastructure Daily Report TLP:GREEN Alert Id: c91b86a6 2026-11-23 04:34:25**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-134654 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134802 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134819 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-134826 (Tier 2)                                                         | 3.k      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting ...           | 1.e      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale              | 1.b      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.c      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.c      |
| Threats    | Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing            | 1.h      |
| Threats    | High volume phishing campaign uses Microsoft 365 outage lures to target multiple | 1.a      |
| Threats    | Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing               | 1.c      |
| Threats    | CVE-2026-134322                                                                  | 1.b      |
| Threats    | CVE-2026-134315                                                                  | 1.b      |
| Threats    | CVE-2026-134312                                                                  | 1.b      |
| Threats    | CVE-2026-134822                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting ...](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.e**

Source: ketch Published: 2026-11-22

Five Eyes agencies issue a joint warning regarding state-sponsored spear-phishing campaigns targeting critical national infrastructure. Operators in energy, transport, and water sectors face tailored attacks designed to harvest credentials and deploy espionage tools. Defenders must prioritize threat intelligence sharing, implement strict email authentication, and conduct regular access reviews for privileged accounts in OT and IT environments.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime)**

**PIR: 1.a**

Source: ketch Published: 2026-11-22

Microsoft researchers dissect the underground infrastructure ecosystem enabling global phishing operations. The report details how threat actors rent domains, proxy servers, and hosting services to scale credential theft campaigns. Infrastructure defenders can leverage these insights to block malicious IP ranges, identify proxy abuse patterns, and harden DNS filtering against fast-flux networks used by cybercriminal syndicates.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale)**

**PIR: 1.b**

Source: ketch Published: 2026-11-22

This analysis reveals how the Tycoon2FA Adversary-in-the-Middle (AiTM) phishing kit bypasses multi-factor authentication at scale. The kit intercepts real-time sessions and relays them to legitimate services, allowing attackers to maintain persistent access. Defenders must implement phishing-resistant MFA methods, monitor for impossible travel and concurrent sessions, and deploy browser-based protections to detect proxy relay behavior.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign)**

**PIR: 1.c**

Source: ketch Published: 2026-11-22

Researchers uncover a novel campaign leveraging AI-generated content to facilitate device code phishing attacks. Attackers automate the creation of convincing landing pages and social engineering prompts to trick users into entering OAuth device codes. This technique bypasses traditional password theft and directly compromises identity tokens. Infrastructure teams should monitor for suspicious OAuth consent requests and restrict device code flows to approved applications.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.c**

Source: ketch Published: 2026-11-22

Microsoft details the EvilTokens toolkit, which exploits device code phishing to steal long-lived identity tokens without capturing passwords. The campaign targets enterprise environments by abusing legitimate OAuth flows to maintain persistent access. Defenders should audit token lifetimes, enforce conditional access policies, and monitor for anomalous device code redemption patterns to detect and revoke compromised sessions early.

___________________________________


# **[Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing](https://dailysecurityreview.com/phishing/operation-hookedwing-4-year-campaign-compromises-500-orgs/)**

**PIR: 1.h**

Source: ketch Published: 2026-11-22

SOCRadar and SecurityWeek analyze Operation HookedWing, a persistent four-year credential-harvesting campaign compromising hundreds of organizations in aviation, energy, and government. Attackers leverage GitHub-hosted phishing pages and automated infrastructure to maintain long-term access. Infrastructure defenders should block known malicious repositories, monitor for credential stuffing attempts, and enforce zero-trust access controls to mitigate lateral movement risks.

___________________________________


# **[High volume phishing campaign uses Microsoft 365 outage lures to target multiple industry sectors](https://microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures)**

**PIR: 1.a**

Source: ketch Published: 2026-11-22

A widespread phishing campaign exploits fake Microsoft 365 outage notifications to harvest credentials across multiple industries. Attackers use highly convincing templates and spoofed sender addresses to trick users into visiting malicious login portals. IT defenders should monitor for anomalous authentication spikes, enforce MFA, and deploy email filtering rules to block known outage-themed lures and suspicious URL patterns.

___________________________________


# **[Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing](https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing)**

**PIR: 1.c**

Source: ketch Published: 2026-11-22

Huntress researchers expose a sophisticated phishing technique disguising device code prompts within legitimate-looking Microsoft Teams booking flows. Attackers manipulate calendar invitation links to redirect users to malicious OAuth consent pages. This method evades traditional email security controls. IT infrastructure teams should validate Teams integration URLs, monitor for unauthorized app registrations, and educate users on verifying booking request sources.

___________________________________


# **[CVE-2026-134322](https://nvd.nist.gov/vuln/detail/CVE-2026-134322)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-21

better-auth 0.4.12-beta.7 before 1.7.16 and 1.8.0-beta.0 before 1.8.0-beta.5 contains an improper authentication vulnerability in the phone number plugin that lets sign-up and other flows save unverified phone numbers, which phone OTP sign-in then uses to select the account. Attackers can attach a victim's number to an attacker-controlled account so the victim's valid OTP sign-in yields a session for that account, exposing data the victim then enters.

___________________________________


# **[CVE-2026-134315](https://nvd.nist.gov/vuln/detail/CVE-2026-134315)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-21

better-auth 1.4.0 before 1.7.16 and 1.8.0-beta.0 before 1.8.0-beta.5 contains an improper authentication vulnerability because email-change links record the old and new addresses but not the requesting user. Attackers can open a still-valid link issued for their own account after a victim registers the attacker's released old address, gaining a session and changing the victim's email to one they control.

___________________________________


# **[CVE-2026-134312](https://nvd.nist.gov/vuln/detail/CVE-2026-134312)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-21

Better Auth 0.4.9 before 1.7.16 and 1.8.0-beta.0 before 1.8.0-beta.5 contains an OAuth sign-in authentication flaw that treats unverified provider emails as verified, including string "false" email_verified claims, unchecked generic OAuth profile/ID-token subject mismatches, and ignored Zoom provider options. Attackers holding a victim's address unverified at an affected provider can sign in, link to the victim's local account, and obtain its session.

___________________________________


# **[CVE-2026-134822](https://nvd.nist.gov/vuln/detail/CVE-2026-134822)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-22

Sustainsys.Saml2 before 1.0.4 and 2.x before 2.11.1 contains an improper signature verification vulnerability that allows attackers to tamper with signed parameters by exploiting mis-parsing in CheckSignature() of Saml2RedirectBinding.cs. Attackers can append data after an extra '=' in RelayState of an intercepted or replayed Redirect-binding message, causing applications to trust the tampered value.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-134654 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134654)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-22

Directly impacts Digital Identity by enabling unauthenticated account takeover via poisoned password-reset links in self-hosted email gateways, compromising credential recovery and session integrity.

*Deep dive: `TIER_2_CVE-2026-134654.md`*

___________________________________


# **[CVE-2026-134802 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134802)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-22

Directly impacts self-hosted SSO/OIDC deployments by bypassing ProxyAuth domain restrictions, compromising authentication and authorization flows in the Digital Identity sector.

*Deep dive: `TIER_2_CVE-2026-134802.md`*

___________________________________


# **[CVE-2026-134819 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134819)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-22

TIER 2 incorrect permission assignment in Delta Sharing server breaks data isolation for authenticated recipients, directly impacting Government inter-agency data exchange and regulated data governance.

*Deep dive: `TIER_2_CVE-2026-134819.md`*

___________________________________


# **[CVE-2026-134826 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-134826)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-22

Finance sector relevance due to unauthenticated manipulation of insurance contract templates and SSRF risks in CRM deployments.

*Deep dive: `TIER_2_CVE-2026-134826.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine