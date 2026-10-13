# Daily phishing and identity campaigns

- **Report date:** 2026-10-12
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.d

This campaign represents a major escalation in threat actor sophistication, shifting from static scripts to fully AI-driven infrastructure and end-to-end automation. Building on the Storm-2372 device code phishing activity observed in early 2025, attackers now leverage machine learning to dynamically generate convincing phishing pages, optimize delivery timing, and automate credential harvesting. IT defenders must prioritize monitoring for anomalous OAuth device code flows and implement AI-aware

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## IR Trends Q2 2026: Phishing and weaponized remote management tools ...

**PIR:** 1.c

A persistent QR code phishing campaign targeting Australian organizations exploits compromised Microsoft 365 accounts to harvest credentials and propagate laterally via internal contact lists. Active through mid-2026, the operation leverages trusted infrastructure to bypass traditional email filters. Defenders should monitor for unusual QR code attachments, enforce strict MFA policies, and audit M365 account permissions to mitigate credential theft and internal campaign propagation.

Source: https://blog.talosintelligence.com/ir-trends-q2-2026/

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.b

Device code phishing has matured into a primary vector for identity takeover, bypassing traditional MFA by tricking users into authorizing attacker-controlled sessions. This analysis details how threat actors exploit OAuth 2.0 device authorization flows to gain persistent access without stealing passwords. Infrastructure teams must implement conditional access policies, monitor for high-frequency device code requests, and educate users on recognizing legitimate authorization prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## We Need to Talk About Device Code Phishing | Huntress

**PIR:** 1.b

Huntress breaks down the mechanics of device code phishing, highlighting why it remains highly effective against modern identity defenses. Attackers leverage legitimate Microsoft authentication endpoints to harvest session tokens, rendering password-based MFA ineffective. The report provides actionable detection strategies, including log analysis for suspicious device code patterns and recommendations for tightening OAuth consent policies to protect enterprise infrastructure.

Source: https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.i

The SideWinder APT group is conducting large-scale credential harvesting by abusing PaaS platforms to host phishing infrastructure at scale. By leveraging cloud deployment services, attackers rapidly provision and rotate malicious domains, evading traditional blocklists. Defenders should monitor for newly registered PaaS-hosted domains mimicking enterprise login portals and implement DNS-level filtering to disrupt this automated identity theft pipeline.

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## Access granted: phishing with device code authorization for account takeover | Proofpoint US

**PIR:** 1.b

This technical deep dive examines how attackers weaponize device code authorization flows to achieve account takeover without direct credential theft. By directing victims to legitimate Microsoft login pages, threat actors capture valid session tokens. The analysis outlines forensic indicators for SOC teams, emphasizing the need to audit OAuth application permissions and deploy real-time alerting for anomalous device code authentication events.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## What is device code phishing, and why are Russian spies so successful at it? - Ars Technica

**PIR:** 1.g

Russian intelligence operatives have perfected device code phishing to hijack Microsoft accounts, exploiting the trust users place in official authentication prompts. This report explores the tradecraft behind these campaigns, including social engineering tactics and infrastructure resilience. IT defenders can learn from these state-sponsored techniques to harden identity perimeters, enforce strict conditional access rules, and improve user awareness training.

Source: https://arstechnica.com/information-technology/2025/02/russian-spies-use-device-code-phishing-to-hijack-microsoft-accounts/

## Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure

**PIR:** 1.f

Laundry Bear leverages a zero-click vulnerability in Zimbra email servers to compromise Western government and critical infrastructure networks without user interaction. This exploit bypasses traditional phishing defenses, granting attackers direct access to email systems and sensitive communications. Infrastructure teams must prioritize patching Zimbra deployments, implement network segmentation, and monitor for lateral movement indicators following initial compromise.

Source: https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure

