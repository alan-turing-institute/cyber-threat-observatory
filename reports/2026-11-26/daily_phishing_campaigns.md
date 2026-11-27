# Daily phishing and identity campaigns

- **Report date:** 2026-11-26
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.a

This analysis dissects the underground infrastructure supporting large-scale phishing operations, revealing how threat actors leverage bulletproof hosting, domain generation algorithms, and proxy networks to evade takedowns. Defenders can use these insights to enhance DNS sinkholing, improve proxy detection rules, and prioritize infrastructure-level blocking over endpoint-only controls.

Source: https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j.3

This campaign utilizes AI-generated landing pages and automated device code flows to bypass traditional email filters and credential harvesting defenses. Attackers trick users into authorizing malicious applications via Microsoft’s device code authentication endpoint, granting direct token access without passwords. Infrastructure defenders should monitor OAuth consent logs, restrict device code flows to approved apps, and deploy AI-detection heuristics.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.j.3

EvilTokens is a novel device code phishing framework that automates token theft by exploiting OAuth 2.0 authorization flows. The tool enables attackers to silently acquire long-lived access tokens, bypassing password resets and MFA prompts. Infrastructure teams must audit OAuth application registrations, enforce token lifetime restrictions, and deploy identity protection solutions that detect anomalous consent grants.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.j.3

Tycoon2FA represents a sophisticated Adversary-in-the-Middle kit that intercepts multi-factor authentication tokens in real-time, rendering traditional MFA ineffective. The kit operates at scale by proxying user sessions and dynamically generating login pages. Defenders must implement phishing-resistant MFA methods like FIDO2 security keys and deploy conditional access policies that block legacy authentication protocols.

Source: https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.j.3

ReversingLabs analyzes a campaign that bypasses password-stealing mechanisms by directly targeting Microsoft 365 device code authentication endpoints. Attackers use automated scripts to harvest authorization codes and exchange them for valid access tokens. Infrastructure defenders should implement conditional access policies that restrict device code usage, monitor for high-frequency token exchanges, and deploy network-level blocking for known malicious OAuth endpoints.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## Resurgence of a multi‑stage AiTM phishing and BEC campaign abusing SharePoint

**PIR:** 1.b

Threat actors combine AiTM proxies with Business Email Compromise tactics, abusing SharePoint permissions to exfiltrate sensitive data after initial account compromise. The multi-stage approach evades standard email security by leveraging legitimate cloud storage APIs. Defenders should enforce least-privilege SharePoint access, monitor for anomalous file sharing patterns, and implement continuous identity risk scoring.

Source: https://microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.c

Proofpoint details how device code phishing has evolved from simple credential harvesting to full identity takeover, leveraging automated consent flows and token theft. The technique circumvents traditional email security and password-based MFA. Defenders should prioritize zero-trust identity architectures, monitor for suspicious OAuth consent events, and educate users on recognizing device code authorization prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## High volume phishing campaign uses Microsoft 365 outage lures to target multiple industry sectors

**PIR:** 1.a

Attackers are exploiting widespread Microsoft 365 service disruptions to distribute high-volume phishing emails mimicking official outage notifications. The campaign targets multiple sectors by leveraging trusted sender domains and urgent language to drive credential harvesting. Infrastructure teams should monitor for anomalous outbound traffic to newly registered domains and validate M365 status through official channels.

Source: https://microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures

