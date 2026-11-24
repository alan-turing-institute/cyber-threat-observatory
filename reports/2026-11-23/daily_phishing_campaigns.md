# Daily phishing and identity campaigns

- **Report date:** 2026-11-23
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.j.3

Researchers expose the EvilTokens toolkit, which automates device code phishing attacks to bypass multi-factor authentication. The report outlines attack flows, token interception techniques, and mitigation strategies for identity administrators. Defenders should review conditional access policies, monitor for suspicious device code requests, and educate users on verifying authorization prompts.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## The risks of device code authentication for AI coding agents

**PIR:** 1.j.3

As AI coding assistants proliferate, attackers are exploiting device code flows to compromise developer accounts and CI/CD pipelines. This advisory highlights how malicious actors trick developers into authorizing rogue tokens, leading to supply chain and infrastructure breaches. Defenders should enforce strict app registration scopes, monitor for unusual device code grants, and restrict AI agent permissions.

Source: https://microsoft.com/en-us/security/blog/2026/11/17/the-risks-of-device-code-authentication-for-ai-coding-agents

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.d

This analysis dissects the underground infrastructure supporting large-scale phishing operations, detailing how threat actors leverage bulletproof hosting, domain generation algorithms, and proxy networks to evade detection. IT defenders can use these insights to enhance DNS filtering, implement advanced URL reputation checks, and monitor for anomalous certificate deployments across their environments.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK

**PIR:** 1.j.3

This technical breakdown tracks the BigBear 2.0 campaign utilizing the Evilginx2 reverse proxy framework to harvest session cookies and bypass MFA. The article provides IOCs, proxy architecture details, and detection rules for SIEM and proxy logs. Infrastructure teams can leverage these indicators to block malicious proxy domains and implement certificate pinning where feasible.

Source: https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign

## Device Code Phishing: An Evolving Technique Impacting SLTTs

**PIR:** 1.j.3

State, local, tribal, and territorial governments face escalating device code phishing attacks targeting cloud identity platforms. The report details campaign trends, common lures, and architectural vulnerabilities in OAuth flows. IT leaders are advised to deploy phishing-resistant MFA, implement continuous access evaluation, and establish rapid incident response playbooks for compromised service accounts.

Source: https://cisecurity.org/insights/blog/device-code-phishing-evolving-technique-impacting-sltts

## Access granted: phishing with device code authorization for account takeover

**PIR:** 1.j.3

This threat intelligence report examines how adversaries leverage device code authorization pages to conduct account takeovers without traditional credential harvesting. Attackers manipulate QR codes and verification URLs to trick users into granting full access. Defenders should monitor for high-frequency device code requests, enforce step-up authentication for sensitive actions, and deploy browser-based detection controls.

Source: https://proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT

**PIR:** 1.a

A Five Eyes joint advisory warns of coordinated spear-phishing operations by state-sponsored actors targeting energy, transportation, and healthcare sectors. The campaign uses highly tailored lures, malicious macros, and living-off-the-land techniques. Infrastructure defenders should prioritize email gateway filtering, disable unnecessary macro execution, and segment critical OT/IT networks to limit lateral movement.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA

**PIR:** 1.a

CISA details a persistent spear-phishing campaign exploiting compromised legitimate credentials and fake login portals to infiltrate diplomatic and governmental networks. The advisory provides technical indicators, email header analysis, and recommended mitigations. Security teams should validate inbound email authentication, enforce least privilege access, and conduct regular phishing simulations for high-value targets.

Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a

