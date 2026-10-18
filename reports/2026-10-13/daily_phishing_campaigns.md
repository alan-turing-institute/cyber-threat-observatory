# Daily phishing and identity campaigns

- **Report date:** 2026-10-13
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.e

Microsoft researchers dissect the underground infrastructure ecosystem fueling global phishing operations. The report details how threat actors leverage bulletproof hosting, domain generation algorithms, and compromised legitimate services to evade takedowns. IT defenders gain actionable intelligence on infrastructure indicators, hosting patterns, and mitigation strategies to disrupt attacker supply chains before campaigns scale.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Joint advisory: state-sponsored spear-phishing campaigns targeting ...

**PIR:** 1.d

A Five Eyes joint advisory warns of state-sponsored spear-phishing campaigns actively targeting critical national infrastructure across energy, transport, and water sectors. The report outlines TTPs, including highly tailored lures and credential harvesting techniques designed to bypass standard email security. Infrastructure operators are urged to implement enhanced monitoring, restrict external access, and validate authentication anomalies immediately.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog

**PIR:** 1.b

Microsoft analyzes the Tycoon2FA kit, a sophisticated Adversary-in-the-Middle platform enabling real-time session hijacking at scale. The breakdown reveals how the kit automates proxying, bypasses MFA, and harvests tokens. Defenders learn to detect proxy traffic patterns, enforce conditional access policies, and deploy browser isolation to neutralize AiTM threats effectively.

Source: https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.c

This investigation traces the EvilTokens campaign, which weaponizes Microsoft’s device code flow to bypass traditional MFA controls. Attackers trick users into entering codes on malicious sites, granting full account access. The article provides detection rules for anomalous device code usage, recommends disabling unnecessary device code flows, and outlines response playbooks for compromised identities.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Phishing campaign exploits OAuth redirection to bypass defenses

**PIR:** 1.c

Researchers uncover campaigns abusing legitimate OAuth protocol redirection to bypass email and web filters. By manipulating callback URLs, attackers route victims to credential harvesting pages while maintaining trusted domain appearances. The analysis highlights the need for strict OAuth scope validation, URL filtering enhancements, and monitoring for unusual authorization requests to protect identity infrastructure.

Source: https://securityaffairs.com/188829/hacking/phishing-campaign-exploits-oauth-redirection-to-bypass-defenses.html

## Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK

**PIR:** 1.b

CloudSEK tracks the BigBear 2.0 campaign leveraging Evilginx2 to conduct large-scale AiTM attacks. The report maps the campaign’s infrastructure, phishing templates, and target sectors. IT teams receive guidance on identifying Evilginx2 proxy signatures, blocking associated domains, and implementing certificate pinning to prevent session token theft and lateral movement.

Source: https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign

## 500+ Org Phishing Campaign: Critical Infrastructure Risk | Satyam ...

**PIR:** 1.d

An analysis of a coordinated phishing wave impacting over 500 organizations in aviation, energy, and logistics. The campaign exploits supply chain trust and uses credential harvesting to pivot into critical systems. Defenders are advised to audit third-party access, enforce strict MFA, monitor for anomalous login patterns, and isolate compromised accounts to prevent infrastructure-wide breaches.

Source: https://www.satyamrastogi.com/blog/500-org-phishing-campaign-supply-chain-critical-infrastructure-2026/

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.c

GhostCode threat actors exploit Microsoft 365 device code authentication to hijack enterprise accounts. The article details how attackers distribute malicious links prompting users to enter verification codes, effectively bypassing MFA. Infrastructure defenders learn to monitor for suspicious device code grants, restrict flow usage via Conditional Access, and deploy user awareness training to mitigate identity takeover risks.

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

