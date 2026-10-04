# Daily phishing and identity campaigns

- **Report date:** 2026-10-03
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.c.1

Microsoft researchers dissect the EvilTokens campaign, detailing how threat actors abuse OAuth device code flows to bypass MFA and harvest valid access tokens. The report outlines infrastructure indicators, token validation bypass techniques, and defensive strategies for identity administrators. IT defenders can leverage these findings to harden conditional access policies, monitor for anomalous device code authorizations, and implement token lifetime restrictions to mitigate identity takeover r

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK

**PIR:** 1.b.2

CloudSEK analyzes the BigBear 2.0 campaign leveraging Evilginx2 to conduct sophisticated proxy-based phishing attacks. The threat group targets enterprise users by hosting malicious reverse proxies that capture session cookies and MFA tokens in real-time. Infrastructure defenders should review proxy logs, implement certificate pinning, and deploy browser isolation solutions. The article provides actionable IOCs and network-level detection rules to block Evilginx2 infrastructure and disrupt crede

Source: https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.d.1

This Microsoft Security Blog post reveals how adversaries integrate generative AI to automate device code phishing at scale. AI models dynamically generate convincing login prompts and adapt to user behavior, significantly increasing success rates. The analysis covers campaign infrastructure, AI prompt engineering techniques, and detection gaps in traditional email security. Defenders are advised to enhance identity monitoring, restrict device code grant types, and deploy behavioral analytics to

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.c.2

Proofpoint examines the tactical shift toward device code phishing as a primary vector for identity compromise. Unlike traditional credential harvesting, this method captures valid OAuth tokens that often bypass step-up authentication. The report details attacker infrastructure, token reuse patterns, and mitigation strategies for cloud identity platforms. IT teams should prioritize monitoring for unusual device code flows, enforce strict conditional access rules, and educate users on recognizing

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## We Need to Talk About Device Code Phishing | Huntress

**PIR:** 1.c.3

Huntress breaks down the tradecraft behind device code phishing, explaining why it poses a severe threat to modern identity architectures. The article walks through the OAuth 2.0 device authorization flow, highlighting how attackers exploit legitimate endpoints to steal tokens. Defenders gain insights into detection methodologies, including SIEM queries for anomalous device code events and recommendations for tightening identity provider configurations to reduce attack surface.

Source: https://www.huntress.com/blog/tradecraft-tuesday-device-code-phishing-explained

## Exposed Server Reveals Three Microsoft 365 Phishing Campaigns

**PIR:** 1.e.1

BreachNews investigates a misconfigured server that inadvertently exposed infrastructure supporting three active Microsoft 365 phishing campaigns. The analysis reveals shared hosting patterns, domain registration tactics, and payload delivery mechanisms targeting enterprise email users. Infrastructure teams can use these findings to improve asset visibility, enforce strict server hardening standards, and implement DNS sinkholing to disrupt campaign infrastructure before user impact.

Source: https://breachnews.com/research/exposed-phishing-infrastructure-reveals-three-active-microsoft-365-campaigns/

## Operation HookedWing: 4 Years, 500 Organizations, 2,000 Credentials

**PIR:** 1.a.1

GBLOCK details a persistent phishing operation that successfully harvested credentials from hundreds of organizations over four years. The campaign utilized customized landing pages, domain spoofing, and credential stuffing follow-ups. The report provides a comprehensive breakdown of attacker infrastructure, TTP evolution, and defensive recommendations. Identity defenders should focus on credential monitoring, implement passwordless authentication, and deploy real-time alerting for compromised a

Source: https://www.gblock.app/articles/operation-hookedwing-four-year-phishing-500-orgs-may-2026

## Access granted: phishing with device code authorization for account takeover | Proofpoint US

**PIR:** 1.c.4

Proofpoint explores the mechanics of device code authorization phishing, demonstrating how attackers trick users into granting access to malicious applications. The article outlines the technical workflow, token persistence risks, and detection challenges for security operations centers. IT infrastructure defenders are guided through implementing token revocation strategies, enhancing user training for authorization prompts, and configuring identity providers to limit device code grant exposure.

Source: https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

