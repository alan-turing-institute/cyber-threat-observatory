# Daily phishing and identity campaigns

- **Report date:** 2026-11-22
- **Sources:** ketch OSINT (3 queries)

## Joint advisory: state-sponsored spear-phishing campaigns targeting ...

**PIR:** 1.e

Five Eyes agencies issue a joint warning regarding state-sponsored spear-phishing campaigns targeting critical national infrastructure. Operators in energy, transport, and water sectors face tailored attacks designed to harvest credentials and deploy espionage tools. Defenders must prioritize threat intelligence sharing, implement strict email authentication, and conduct regular access reviews for privileged accounts in OT and IT environments.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.a

Microsoft researchers dissect the underground infrastructure ecosystem enabling global phishing operations. The report details how threat actors rent domains, proxy servers, and hosting services to scale credential theft campaigns. Infrastructure defenders can leverage these insights to block malicious IP ranges, identify proxy abuse patterns, and harden DNS filtering against fast-flux networks used by cybercriminal syndicates.

Source: https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.b

This analysis reveals how the Tycoon2FA Adversary-in-the-Middle (AiTM) phishing kit bypasses multi-factor authentication at scale. The kit intercepts real-time sessions and relays them to legitimate services, allowing attackers to maintain persistent access. Defenders must implement phishing-resistant MFA methods, monitor for impossible travel and concurrent sessions, and deploy browser-based protections to detect proxy relay behavior.

Source: https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.c

Researchers uncover a novel campaign leveraging AI-generated content to facilitate device code phishing attacks. Attackers automate the creation of convincing landing pages and social engineering prompts to trick users into entering OAuth device codes. This technique bypasses traditional password theft and directly compromises identity tokens. Infrastructure teams should monitor for suspicious OAuth consent requests and restrict device code flows to approved applications.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.c

Microsoft details the EvilTokens toolkit, which exploits device code phishing to steal long-lived identity tokens without capturing passwords. The campaign targets enterprise environments by abusing legitimate OAuth flows to maintain persistent access. Defenders should audit token lifetimes, enforce conditional access policies, and monitor for anomalous device code redemption patterns to detect and revoke compromised sessions early.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing

**PIR:** 1.h

SOCRadar and SecurityWeek analyze Operation HookedWing, a persistent four-year credential-harvesting campaign compromising hundreds of organizations in aviation, energy, and government. Attackers leverage GitHub-hosted phishing pages and automated infrastructure to maintain long-term access. Infrastructure defenders should block known malicious repositories, monitor for credential stuffing attempts, and enforce zero-trust access controls to mitigate lateral movement risks.

Source: https://dailysecurityreview.com/phishing/operation-hookedwing-4-year-campaign-compromises-500-orgs/

## High volume phishing campaign uses Microsoft 365 outage lures to target multiple industry sectors

**PIR:** 1.a

A widespread phishing campaign exploits fake Microsoft 365 outage notifications to harvest credentials across multiple industries. Attackers use highly convincing templates and spoofed sender addresses to trick users into visiting malicious login portals. IT defenders should monitor for anomalous authentication spikes, enforce MFA, and deploy email filtering rules to block known outage-themed lures and suspicious URL patterns.

Source: https://microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures

## Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing

**PIR:** 1.c

Huntress researchers expose a sophisticated phishing technique disguising device code prompts within legitimate-looking Microsoft Teams booking flows. Attackers manipulate calendar invitation links to redirect users to malicious OAuth consent pages. This method evades traditional email security controls. IT infrastructure teams should validate Teams integration URLs, monitor for unauthorized app registrations, and educate users on verifying booking request sources.

Source: https://www.huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing

