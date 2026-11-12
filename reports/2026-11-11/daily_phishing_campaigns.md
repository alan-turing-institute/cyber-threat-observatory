# Daily phishing and identity campaigns

- **Report date:** 2026-11-11
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.a

Analyzes the underground infrastructure powering modern phishing operations, detailing proxy networks, domain generation algorithms, and hosting providers. Provides actionable indicators for blocking upstream infrastructure and disrupting attacker supply chains before campaigns scale.

Source: https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.b.2

Dissects the EvilTokens PhaaS platform, revealing how device code phishing bypasses MFA by hijacking OAuth consent flows. Includes network signatures, consent URL patterns, and detection logic for SIEM and identity protection tools.

Source: https://aka.ms/EvilTokens-PhaaS

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.b.1

Examines the Tycoon2FA AiTM kit architecture, highlighting its reverse proxy capabilities, session token harvesting, and automated scaling mechanisms. Offers infrastructure defenders IOCs, proxy fingerprinting techniques, and mitigation strategies for token-based authentication.

Source: https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.b.2

Explores how device code phishing has matured into a primary identity takeover vector, circumventing traditional password and MFA controls. Details attack workflows, consent manipulation tactics, and architectural recommendations for zero-trust identity validation.

Source: https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.b.2

Investigates a campaign leveraging AI to dynamically generate phishing pages and automate device code harvesting. Highlights behavioral anomalies in OAuth flows, provides detection rules for anomalous consent requests, and outlines infrastructure hardening steps.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing

**PIR:** 1.c.1

Reveals how attackers abuse Microsoft Teams booking workflows to deliver device code phishing payloads. Analyzes the abuse of legitimate collaboration features, provides Teams-specific detection queries, and recommends conditional access policies to block unauthorized consent.

Source: https://huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing

## Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise

**PIR:** 1.b.1

Details a multi-stage campaign using fake compliance training to harvest AiTM tokens. Breaks down the social engineering narrative, proxy infrastructure, and token exfiltration methods, offering defenders playbook-based detection and response guidance.

Source: https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise

## Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA

**PIR:** 1.d.1

CISA advisory on a targeted spearphishing operation exploiting document macros and credential harvesting portals. Provides threat actor TTPs, infrastructure indicators, and defensive recommendations for securing email gateways and identity perimeters.

Source: https://cisa.gov/uscert/ncas/alerts/aa21-148a

