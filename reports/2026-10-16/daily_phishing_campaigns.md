# Daily phishing and identity campaigns

- **Report date:** 2026-10-16
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.g.1

Microsoft Security researchers dissect the sprawling infrastructure ecosystem fueling global phishing campaigns. The report details how threat actors leverage compromised domains, bulletproof hosting, and automated domain generation algorithms to evade takedowns. Infrastructure defenders will find actionable IOCs, architectural breakdowns of proxy networks, and mitigation strategies for disrupting these resilient criminal supply chains at the network level.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog

**PIR:** 1.i.1

Microsoft researchers expose a sophisticated campaign combining AI-generated lures with Microsoft’s Device Authorization Grant flow. Attackers use machine learning to craft highly personalized emails that trick users into entering device codes. The article provides detection queries for Entra ID, highlights behavioral anomalies in OAuth consent logs, and outlines policy hardening steps to block malicious approvals.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.f.1

This technical breakdown traces the EvilTokens toolkit to its core mechanisms, explaining how it exploits legitimate OAuth device code flows to steal valid access tokens. The report details the attacker’s infrastructure, token persistence techniques, and evasion tactics. IT defenders gain critical guidance on monitoring Azure AD sign-in logs, restricting device code grant policies, and deploying conditional access rules.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.e.1

A deep dive into the Tycoon2FA adversary-in-the-middle phishing kit, revealing how attackers bypassed multi-factor authentication at scale. The analysis covers the kit’s reverse-proxy architecture, session hijacking techniques, and deployment patterns. Security teams can leverage these insights to configure WAF rules, monitor for suspicious proxy traffic, and implement certificate pinning to neutralize AiTM threats.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK

**PIR:** 1.e.2

CloudSEK tracks the BigBear 2.0 campaign leveraging the open-source Evilginx2 framework to conduct large-scale AiTM attacks. The analysis maps the campaign’s infrastructure, domain registration patterns, and target sectors. Defenders receive actionable network indicators, DNS sinkhole recommendations, and browser extension deployment strategies to intercept proxy-based credential harvesting before session tokens are exfiltrated.

Source: https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.f.2

Proofpoint examines the rapid proliferation of device code phishing, driven by publicly available toolkits and phishing-as-a-service models. The report highlights how attackers bypass traditional MFA by hijacking OAuth consent workflows. Infrastructure teams are advised to audit third-party app permissions, implement strict conditional access policies, and deploy user training focused on recognizing device code prompts.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.g.2

Breakglass Intelligence details how the SideWinder APT group abuses Platform-as-a-Service environments to host credential harvesting infrastructure at scale. The report outlines the group’s use of ephemeral cloud instances, automated domain provisioning, and legitimate SaaS integrations to evade detection. Defenders learn how to monitor cloud deployment logs, restrict PaaS permissions, and detect anomalous hosting patterns.

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...

**PIR:** 1.f.3

ReversingLabs documents an active Microsoft 365 campaign that sidesteps traditional password harvesting by abusing the Device Authorization Grant flow. Attackers deploy polished, business-themed lures to trick users into authorizing malicious apps. The article provides email headers, phishing kit URLs, and Microsoft Graph API queries to identify compromised accounts and revoke unauthorized device code grants.

Source: https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/

