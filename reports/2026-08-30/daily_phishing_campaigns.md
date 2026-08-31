# Daily phishing and identity campaigns

- **Report date:** 2026-08-30
- **Sources:** ketch OSINT (3 queries)

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.f

Device code phishing is rapidly evolving as a primary vector for identity compromise, driven by publicly available toolkits and phishing-as-a-service models. Attackers manipulate Microsoft’s Device Authorization Grant flow to trick users into approving malicious OAuth tokens. This technique bypasses password theft and traditional MFA. Infrastructure teams should monitor for unusual device code approvals, restrict OAuth app consent policies, and educate users on recognizing device code prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Mirage2FA Phishing Kit Bypasses MFA to Hijack Microsoft 365 Sessions, Targeting 3,500+ Organizations - Cyber Accord

**PIR:** 1.e

The Mirage2FA kit exploits Microsoft 365 authentication flows to bypass multi-factor authentication and steal active user sessions. Targeting over 3,500 organizations, the campaign uses real-time proxying to capture MFA tokens and session cookies. Infrastructure defenders must prioritize MFA fatigue detection, enforce phishing-resistant authentication methods like FIDO2, and monitor for impossible travel or concurrent session anomalies in Azure AD logs.

Source: https://www.cyberaccord.com/mirage2fa-phishing-kit-bypasses-mfa-to-hijack-microsoft-365-sessions-targeting-3500-organizations/

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.h

Microsoft researchers detail a campaign combining AI-generated lures with automated device code phishing to scale account compromises. Threat actors use end-to-end automation to generate live authentication codes on demand, significantly increasing success rates and maintaining persistent access. Defenders should leverage Microsoft Graph security APIs to detect anomalous consent grants, enforce just-in-time access, and deploy AI-driven email filtering to block synthetic phishing content.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Chained Account Takeovers: AiTM Phishing Campaign Propagating Across Healthcare and Academic Medical Institutions - Security Risk Advisors

**PIR:** 1.d

A sophisticated Adversary-in-the-Middle (AiTM) campaign is chaining account takeovers across healthcare and academic medical networks. Attackers use live proxying to capture credentials and MFA tokens, then pivot laterally using compromised Outlook accounts. Defenders should implement email authentication hardening, deploy AI-driven anomaly detection for login patterns, and restrict cross-tenant sharing to contain lateral movement.

Source: https://sra.io/blog/chained-account-takeovers-aitm-phishing-campaign-propagating-across-healthcare-and-academic-medical-institutions/

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.f

ReversingLabs analysts document an active campaign abusing Microsoft’s Device Authorization Grant flow to execute near-invisible account takeovers. The attack combines realistic business-themed lures with a polished phishing kit, tricking users into authorizing malicious OAuth tokens. This bypasses traditional credential harvesting. Infrastructure teams must audit registered OAuth applications, enforce user consent restrictions, and monitor for high-privilege token issuance in identity logs.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

## NovaCookies at scale: Inside the $320 Phishing Service Targeting Hundreds of Organizations

**PIR:** 1.g

Threat actors are leveraging the NovaCookies phishing-as-a-service platform to conduct large-scale credential harvesting campaigns. Priced at just $320, this service enables low-skill attackers to target hundreds of organizations simultaneously. The infrastructure relies on automated proxying and real-time session interception, bypassing traditional email filters. Defenders should monitor for anomalous OAuth consent requests and implement strict conditional access policies to mitigate session hi

Source: https://www.island.io/blog/novacookies-at-scale-inside-the-320-phishing-service-targeting-hundreds-of-organizations

## Procurement-Themed AiTM Campaign Hijacks Microsoft 365 Sessions via Compromised Outlook Accounts | Mallory

**PIR:** 1.i

Attackers are deploying procurement-themed Adversary-in-the-Middle phishing kits to hijack Microsoft 365 sessions. By compromising initial Outlook accounts, threat actors send highly convincing vendor invoice lures that proxy real login portals. This enables seamless MFA bypass and session theft. IT defenders should implement strict email routing rules for procurement domains, monitor for session token reuse, and enforce phishing-resistant MFA for finance workflows.

Source: https://mallory.ai/stories/019f864d-cd13-7094-9964-55c354477637

## TIDALGUEST: A Self-Replicating Invitation Phishing Cluster | AegisAI

**PIR:** 1.a

The TIDALGUEST cluster utilizes self-replicating invitation phishing to infiltrate corporate networks. Compromised accounts automatically generate and distribute malicious calendar and meeting invites, propagating the campaign across domains. This technique exploits trust in internal communication channels. Defenders should monitor for anomalous calendar creation patterns, restrict external meeting invites, and deploy behavioral analytics to detect automated invitation generation.

Source: https://www.aegisai.ai/blog/tidalguest-invitation-phishing-cluster

