# **Infrastructure Daily Brief: 2026-10-25**

**Infrastructure Daily Report TLP:GREEN Alert Id: 8f7651ae 2026-10-26 03:51:47**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-116000 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-116006 (Tier 2)                                                         | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.j.3    |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j.3    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.j.3    |
| Threats    | Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target West | 1.a      |
| Threats    | Access granted: phishing with device code authorization for account takeover | P | 1.j.3    |
| Threats    | SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale     | 1.d      |
| Threats    | Storm-2372 conducts device code phishing campaign | Microsoft Security Blog      | 1.j.3    |
| Threats    | Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government A | 1.a      |
| Threats    | CVE-2026-116163                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-25

EvilTokens represents a sophisticated evolution in device code phishing, where threat actors harvest long-lived authentication tokens rather than just session cookies. By targeting the underlying OAuth 2.0 device authorization flow, attackers achieve persistent access that survives password resets and MFA re-registration. This analysis details the technical mechanics of EvilTokens and provides actionable mitigation strategies for identity architects, emphasizing the need for token lifecycle mana

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-25

This campaign marks a significant escalation in threat actor sophistication, moving away from static, manual scripts toward an AI-driven infrastructure with end-to-end automation. It builds upon the Storm-2372 device code phishing campaign observed in February 2025, demonstrating how adversaries are leveraging generative AI to streamline credential harvesting and bypass traditional MFA controls. Infrastructure defenders should monitor for automated OAuth consent requests and implement strict con

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-25

Device code phishing continues to evolve as a primary vector for identity takeover, exploiting the convenience of multi-device authentication flows. Attackers now deploy sophisticated landing pages that mimic legitimate OAuth consent prompts, tricking users into authorizing malicious applications. This technique effectively circumvents traditional password-based MFA, making it a critical threat for organizations relying on cloud identity platforms. Defenders must prioritize user education and im

___________________________________


# **[Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure](https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure)**

**PIR: 1.a**

Source: ketch Published: 2026-10-25

Laundry Bear, a Russian threat actor, is exploiting a zero-click vulnerability in Zimbra collaboration software to compromise Western government and critical infrastructure networks. The attack requires no user interaction, bypassing traditional email security controls and directly harvesting credentials or deploying backdoors. Infrastructure defenders must prioritize patching Zimbra instances, implementing network segmentation, and deploying endpoint detection and response solutions to mitigate

___________________________________


# **[Access granted: phishing with device code authorization for account takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-25

This report details how threat actors leverage device code authorization flows to execute account takeover attacks at scale. By directing users to counterfeit Microsoft 365 login portals, attackers capture the six-character device codes and exchange them for valid access tokens. The campaign highlights vulnerabilities in default cloud configurations and underscores the necessity of enforcing app consent policies, monitoring for anomalous OAuth grants, and deploying identity protection solutions.

___________________________________


# **[SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale](https://intel.breakglass.tech/post/sidewinder-mhil-zeabur)**

**PIR: 1.d**

Source: ketch Published: 2026-10-25

The SideWinder APT group is conducting a large-scale credential harvesting campaign by abusing Platform-as-a-Service infrastructure to host phishing domains and proxy traffic. This approach allows attackers to rapidly deploy and rotate malicious infrastructure while evading traditional blocklists. The campaign targets enterprise users to steal cloud credentials, highlighting the need for DNS filtering, threat intelligence integration, and continuous monitoring of cloud-hosted phishing infrastruc

___________________________________


# **[Storm-2372 conducts device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-25

Storm-2372, a Chinese state-sponsored threat group, deployed a targeted device code phishing campaign against government and enterprise targets. The operation utilized customized landing pages and social engineering to harvest OAuth device codes, enabling persistent access to compromised accounts. This campaign illustrates the growing reliance of advanced persistent threats on identity-centric attack vectors, prompting defenders to strengthen conditional access rules and monitor for unauthorized

___________________________________


# **[Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies](https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies)**

**PIR: 1.a**

Source: ketch Published: 2026-10-25

Three concurrent phishing campaigns are actively targeting educational institutions and government agencies using Microsoft 365 infrastructure. Attackers deploy credential harvesting pages mimicking Office 365 login portals, often distributed via malicious email attachments or links. The campaigns exploit weak email filtering configurations and lack of multi-factor authentication. Defenders should review mail flow rules, enforce MFA, and monitor for suspicious sign-in locations and impossible tr

___________________________________


# **[CVE-2026-116163](https://nvd.nist.gov/vuln/detail/CVE-2026-116163)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-25

Parse Server before 8.6.102 and 9.0.0 before 9.10.5-alpha.2 contains an authentication bypass because the validateSetUp, validateLogin, and validateUpdate methods of custom adapters subclassing AuthAdapter are never called, and an inherited default that accepts any authData is used instead. Attackers can supply arbitrary authData to sign up, link identities, log in as existing users, or skip custom additional authentication factors.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-116000 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116000)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-25

TIER 2 SSRF/path traversal in on-premise AI RAG framework explicitly deployed in Finance, Healthcare, and Government for sensitive document processing.

*Deep dive: `TIER_2_CVE-2026-116000.md`*

___________________________________


# **[CVE-2026-116006 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116006)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-25

Direct authentication bypass in a widely deployed enterprise/public-sector backend framework, compromising SMS verification and token issuance for full admin takeover.

*Deep dive: `TIER_2_CVE-2026-116006.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine