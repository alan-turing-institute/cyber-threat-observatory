# Daily phishing and identity campaigns

- **Report date:** 2026-10-15
- **Sources:** ketch OSINT (3 queries)

## Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure

**PIR:** 1.j.3

Russian threat group Laundry Bear is exploiting a critical zero-click vulnerability in Zimbra collaboration suites to infiltrate Western government and critical infrastructure networks. The exploit allows remote code execution without user interaction, bypassing traditional email security controls. Defenders should immediately patch Zimbra instances, isolate affected mail servers, and deploy network detection rules for known C2 traffic patterns.

Source: https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.b

The SideWinder APT group has escalated its operations by abusing Platform-as-a-Service environments to host credential harvesting infrastructure at scale. By leveraging legitimate cloud services, attackers evade traditional blocklists and deploy highly convincing login pages. Infrastructure teams must implement strict egress filtering, monitor for unauthorized PaaS deployments, and deploy conditional access policies to detect compromised credentials.

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies

**PIR:** 1.a

Threat actors are actively deploying sophisticated phishing campaigns leveraging Microsoft 365 infrastructure to compromise educational and government networks. These campaigns utilize credential harvesting portals, malicious document attachments, and impersonation tactics to bypass standard email filters. IT defenders should monitor for anomalous sign-in locations, enforce MFA, and review shared mailbox permissions to mitigate lateral movement risks.

Source: https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies

## Capacity Enhancement Guide: Counter-Phishing Recommendations for Federal Agencies

**PIR:** 1.d

This CISA publication provides actionable counter-phishing strategies tailored for federal IT environments. It outlines best practices for email authentication enforcement, security awareness training, and incident response workflows. Agencies are advised to implement DMARC monitoring, restrict external forwarding, and establish rapid credential reset protocols to minimize the impact of successful phishing attempts across critical infrastructure systems.

Source: https://cisa.gov/sites/default/files/publications/Capacity_Enhancement_Guide-Counter-Phishing_Recommendations_for_Federal_Agencies.pdf

