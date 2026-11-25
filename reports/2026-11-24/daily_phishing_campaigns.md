# Daily phishing and identity campaigns

- **Report date:** 2026-11-24
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j.3

This campaign leverages AI to automate the generation and delivery of Microsoft Device Authorization Grant codes, enabling seamless account takeover without traditional password theft. Attackers use machine learning to mimic legitimate device code prompts and scale operations across thousands of targets. Defenders should monitor OAuth consent logs for suspicious device code grants, enforce app consent policies, and restrict interactive device code flows to approved corporate devices.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.i

Tycoon2FA is a sophisticated Adversary-in-the-Middle phishing kit that intercepts multi-factor authentication tokens in real-time. It proxies user sessions to legitimate login portals, capturing cookies and session tokens to bypass MFA. Infrastructure teams must implement phishing-resistant MFA, monitor for anomalous proxy traffic patterns, and deploy conditional access policies that restrict token reuse across disparate IP geolocations.

Source: https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j

Device code phishing is rapidly evolving as a primary identity takeover vector, driven by publicly available toolkits and Phishing-as-a-Service models. Attackers exploit OAuth 2.0 device authorization flows to bypass traditional password-based defenses. Security teams should implement strict OAuth consent policies, monitor for high-frequency device code requests, and deploy identity-aware proxies to validate authentication contexts before granting access.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.e

Threat actors leverage a decentralized, resilient phishing infrastructure ecosystem that dynamically provisions domains, email services, and hosting to evade takedowns. This report details architectural patterns, including abuse of cloud providers and bulletproof hosting, enabling rapid campaign scaling. Infrastructure defenders should monitor for newly registered domains with shared ASN footprints, analyze DNS tunneling indicators, and implement proactive sinkholing strategies to disrupt the un

Source: https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime

## Resurgence of a multi‑stage AiTM phishing and BEC campaign abusing SharePoint

**PIR:** 1.f

A multi-stage campaign combines AiTM phishing with Business Email Compromise by abusing SharePoint file sharing permissions. Attackers harvest credentials, then manipulate SharePoint access controls to exfiltrate sensitive documents and pivot laterally. IT infrastructure defenders must audit SharePoint sharing settings, enforce least-privilege access, monitor for anomalous file permission changes, and integrate identity threat detection with cloud storage telemetry.

Source: https://microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT

**PIR:** 1.a

Five Eyes agencies issue a joint advisory on state-sponsored spear-phishing campaigns targeting critical infrastructure sectors. Threat actors use highly tailored lures, compromised legitimate credentials, and advanced evasion techniques to infiltrate networks. Defenders should prioritize threat intelligence sharing, implement strict email authentication, monitor for lateral movement indicators, and ensure incident response playbooks address state-level adversary TTPs.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.j

Analysts document a campaign utilizing Microsoft’s Device Authorization Grant flow to achieve near-invisible account takeover. By combining realistic business lures with polished phishing kits, attackers bypass password theft entirely. Infrastructure defenders must audit Azure AD sign-in logs for device code authentication events, restrict OAuth app permissions, and implement continuous authentication monitoring to detect token hijacking attempts.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## High volume phishing campaign uses Microsoft 365 outage lures to target multiple industry sectors

**PIR:** 1.a

A high-volume campaign exploits Microsoft 365 service outage notifications to trick users into credential submission. Attackers use spoofed sender addresses and urgent language to bypass initial email filters. Defenders should review mail flow rules for spoofed internal domains, enforce DMARC/DKIM/SPF strict alignment, and deploy user awareness training focused on service status verification via official channels rather than email links.

Source: https://microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures

