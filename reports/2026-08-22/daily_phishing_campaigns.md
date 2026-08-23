# Daily phishing and identity campaigns

- **Report date:** 2026-08-22
- **Sources:** ketch OSINT (3 queries)

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.b

This analysis details how device code phishing effectively neutralizes multi-factor authentication by leveraging legitimate OAuth mechanisms. Attackers host fake verification pages that prompt users to enter codes, instantly granting session tokens. Defenders must shift from password-centric security to identity-centric monitoring, implementing zero-trust access controls, restricting device flow usage, and deploying behavioral analytics to detect unauthorized consent grants.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog

**PIR:** 1.c

Illicit consent grants have escalated with AI-powered phishing-as-a-service platforms automating device code attacks. These campaigns exploit OAuth misconfigurations to harvest long-lived access tokens without user passwords. IT infrastructure teams must audit registered applications, enforce least-privilege consent policies, and deploy identity protection solutions that detect and revoke anomalous token issuance in real time.

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## A New Era Of Social Engineering: The Device Code Phishing Boom

**PIR:** 1.b

Device code phishing has emerged as a dominant threat vector, bypassing traditional multi-factor authentication by tricking users into entering authorization codes on attacker-controlled devices. This technique leverages OAuth 2.0 device flow vulnerabilities, allowing threat actors to hijack sessions without capturing passwords. IT defenders must monitor for anomalous device code requests, implement conditional access policies, and educate users on recognizing fake verification prompts to mitiga

Source: https://coalitioninc.com/blog/security-labs/a-new-era-of-social-engineering-the-device-code-phishing-boom

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.e

Zero-click phishing campaigns targeting Zimbra email servers allow threat actors to bypass user interaction entirely. By exploiting server-side vulnerabilities, attackers inject malicious payloads that execute upon email processing. CISA warns organizations to immediately patch Zimbra instances, segment email infrastructure, and deploy network-level detection to block command-and-control traffic associated with this campaign.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.b

Recent threat intelligence reveals a massive surge in device code phishing campaigns targeting enterprise environments. Attackers are deploying sophisticated landing pages that mimic legitimate SSO portals, prompting users to input device codes that grant immediate account access. Security teams should prioritize blocking unauthorized OAuth applications, enabling real-time alerting for device flow authentication attempts, and deploying browser isolation to intercept malicious verification reques

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.b

Identity takeover attacks have evolved beyond credential stuffing to exploit the OAuth device authorization grant. By coercing users into submitting device codes, adversaries bypass password policies and MFA controls entirely. Infrastructure defenders must treat device code submissions as high-risk events, enforce strict conditional access rules, and integrate identity threat detection platforms to flag suspicious authorization flows before lateral movement occurs.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.d

Active phishing campaigns are exploiting Microsoft 365 infrastructure to compromise educational and government networks. Attackers use tailored lures mimicking internal communications to harvest credentials and deploy malicious macros. Defenders should enforce strict email filtering, disable legacy authentication protocols, and implement automated incident response playbooks to contain breaches and protect sensitive institutional data.

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

## Russian Hackers Trick Academics and Diplomats Into Giving Them Access to Email and WhatsApp

**PIR:** 1.d

State-sponsored actors are deploying highly targeted phishing operations against academics and diplomatic personnel to compromise email and messaging platforms. These campaigns leverage social engineering and credential harvesting to establish persistent access. Infrastructure defenders must prioritize executive protection programs, enforce strict MFA with phishing-resistant methods, and monitor for anomalous login patterns across communication services.

Source: https://cyberpress.org/russian-hackers-breach-diplomat-accounts

