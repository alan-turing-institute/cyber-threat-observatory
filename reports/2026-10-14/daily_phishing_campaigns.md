# Daily phishing and identity campaigns

- **Report date:** 2026-10-14
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.j.3

This report dissects the underground infrastructure supporting global phishing operations, detailing how threat actors leverage bulletproof hosting, domain generation algorithms, and proxy networks to evade takedowns. IT defenders can use these indicators to enhance DNS sinkholing, improve proxy filtering, and strengthen domain reputation scoring. The analysis highlights emerging infrastructure-as-a-service models that lower barriers to entry for cybercriminals, requiring proactive threat huntin

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.e

An in-depth technical breakdown of the Tycoon2FA adversary-in-the-middle phishing kit, which bypasses multi-factor authentication by proxying real-time sessions between victims and legitimate login portals. The article details the kit architecture, session hijacking mechanisms, and deployment tactics. Infrastructure defenders should review reverse proxy configurations, implement certificate pinning, and deploy behavioral analytics to detect anomalous session handshakes and unauthorized token rel

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.f

This investigation traces the EvilTokens campaign, which exploits Microsoft device code authentication flow to harvest OAuth tokens without triggering traditional MFA alerts. Attackers distribute malicious links prompting users to enter verification codes, granting threat actors persistent access. Defenders must monitor for suspicious device code consent events, restrict OAuth app permissions, and implement conditional access policies that block token issuance from untrusted networks or unfamili

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## AI-powered phishkit arms criminals with account-hijacking tools in 10 minutes | Malwarebytes

**PIR:** 1.i

Malwarebytes researchers detail a new AI-driven phishing kit that automates the creation of highly convincing credential-harvesting pages in under ten minutes. The tool leverages large language models to dynamically generate context-aware copy, logos, and layout variations, significantly increasing success rates. IT teams should prioritize email content filtering, deploy browser isolation, and train users to recognize subtle UI inconsistencies. Automated threat intelligence feeds can help block 

Source: https://www.malwarebytes.com/blog/threat-intel/2026/10/ai-powered-phishkit-arms-criminals-with-account-hijacking-tools-in-10-minutes

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.f

GhostCode threat actors are actively abusing Microsoft 365 device code authentication to compromise enterprise accounts. By tricking users into authorizing malicious OAuth applications, attackers gain persistent access to email, files, and collaboration tools. The report outlines detection signatures for suspicious consent grants, recommends restricting third-party app integrations, and provides guidance on revoking compromised tokens. Infrastructure teams should audit Azure AD sign-in logs for 

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.d

This analysis covers the SideWinder APT group credential harvesting campaign, which abuses public cloud PaaS platforms to host phishing infrastructure at scale. By leveraging legitimate cloud services, attackers bypass traditional perimeter defenses and rapidly deploy credential theft portals. Defenders should monitor for newly registered cloud-hosted domains, implement strict egress filtering, and deploy cloud access security broker controls to detect and block unauthorized PaaS usage for malic

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## Device Code Phishing Hits 340+ Microsoft 365 Orgs Across Five Countries via OAuth Abuse

**PIR:** 1.f

A cross-border campaign targeting Microsoft 365 organizations across five countries exploits OAuth device code flows to bypass traditional authentication controls. Attackers distribute malicious links via email and messaging platforms, prompting users to enter verification codes that grant unauthorized app access. The report provides IOCs, detection queries for Azure AD, and mitigation steps including conditional access restrictions and user awareness training. Infrastructure defenders should pr

Source: https://news.u-labs.de/link?id=30726

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.d

This briefing details three concurrent phishing campaigns specifically targeting educational and government Microsoft 365 tenants. Attackers use tailored lures referencing compliance deadlines and system updates to harvest credentials and deploy malicious OAuth apps. The article includes email headers, malicious URLs, and recommended firewall rules. IT infrastructure teams should update email security gateways, enforce strict URL filtering, and validate third-party application permissions across

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

