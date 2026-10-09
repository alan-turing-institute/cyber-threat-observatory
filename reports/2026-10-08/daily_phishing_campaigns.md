# Daily phishing and identity campaigns

- **Report date:** 2026-10-08
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.g.2

Microsoft details a sophisticated phishing campaign leveraging AI-driven infrastructure to automate device code authorization requests. Unlike previous manual scripts, this operation uses end-to-end automation to bypass traditional defenses and facilitate rapid account takeovers. The campaign represents a significant escalation in threat actor sophistication, building upon techniques observed in the Storm-2372 campaign. Defenders should monitor OAuth consent logs, restrict device code flows, and

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Access granted: phishing with device code authorization for account takeover | Proofpoint US

**PIR:** 1.g.1

Proofpoint analyzes how threat actors exploit device code authorization flows to bypass multi-factor authentication and achieve account takeover. The report outlines the technical mechanics of the OAuth abuse, highlighting how attackers trick users into entering codes on malicious portals. Infrastructure defenders are advised to audit conditional access policies, disable unnecessary device code grants, and deploy real-time alerting for suspicious consent events to protect enterprise identities.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j.3

This analysis tracks the rapid evolution of device code phishing as a primary vector for identity takeover. Attackers increasingly target cloud environments by abusing legitimate OAuth endpoints, rendering traditional email filtering ineffective. The article provides actionable mitigation strategies for IT defenders, including implementing token-bound sessions, enforcing strict consent policies, and integrating identity threat detection platforms to monitor anomalous authorization patterns acros

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## We Need to Talk About Device Code Phishing | Huntress

**PIR:** 1.g.1

Huntress breaks down the tradecraft behind device code phishing campaigns, explaining how attackers leverage legitimate cloud authentication mechanisms to compromise accounts. The guide covers detection signatures, incident response playbooks, and architectural changes required to harden identity perimeters. IT infrastructure teams will find practical steps to reduce attack surface, including restricting OAuth app permissions and deploying behavioral analytics to catch automated consent abuse.

Source: https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.g.2

Aegis AI attributes automated device code phishing campaigns to GTG-20006, a threat group linked to the Midnight Blizzard APT. The report details how the actor integrates AI tools to scale credential harvesting and bypass identity protections. Infrastructure defenders should correlate threat intelligence feeds with identity logs, monitor for anomalous device code generation patterns, and enforce zero-trust access controls to mitigate state-sponsored identity theft operations.

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## AI-enabled device code phishing campaign exploits OAuth flow for account takeover - Help Net Security

**PIR:** 1.f.2

Help Net Security reports on an AI-enhanced phishing operation that weaponizes OAuth device code flows for large-scale account takeover. The campaign demonstrates how machine learning models optimize phishing page generation and victim targeting in real time. Defenders are urged to update SIEM rules for OAuth abuse, implement step-up authentication for sensitive actions, and educate users on recognizing AI-crafted social engineering prompts targeting device authorization screens.

Source: https://www.helpnetsecurity.com/2026/04/07/microsoft-device-code-phishing-campaign/

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.h.1

CISA alerts organizations to a zero-click phishing campaign targeting Zimbra email servers, attributed to the Laundry Bear threat group. The attack exploits unpatched vulnerabilities to deliver malicious payloads without user interaction, bypassing traditional email security gateways. Infrastructure teams should immediately apply vendor patches, segment email server infrastructure, and deploy network-level anomaly detection to identify exploitation attempts against legacy collaboration platforms

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs

**PIR:** 1.i.1

Secure Bulletin investigates PhantomEnigma, a malware distribution network that compromises legitimate government websites to host malicious payloads. By leveraging trusted domains, attackers evade reputation-based security controls and deliver malware to unsuspecting users. IT defenders must implement strict web traffic filtering, monitor for unauthorized content changes on public-facing infrastructure, and deploy endpoint detection to catch supply-chain-style web compromises.

Source: https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs

