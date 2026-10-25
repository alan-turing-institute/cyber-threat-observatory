# **Infrastructure Daily Brief: 2026-10-24**

**Infrastructure Daily Report TLP:GREEN Alert Id: d4816000 2026-10-25 01:57:24**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-114191 (Tier 2)                                                         | 3.k      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.h      |
| Threats    | Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft  | 1.e      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.f      |
| Threats    | Operation HookedWing: Four-Year Phishing Campaign Hits 500+ Organizations in Avi | 1.i      |
| Threats    | Talos: Attackers Refine Phishing Playbook To Target Critical Infrastructure      | 1.i      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.f      |
| Threats    | Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365  | 1.f      |
| Threats    | CVE-2026-115547                                                                  | 1.b      |
| Threats    | CVE-2026-79977                                                                   | 1.b      |
| Threats    | CVE-2026-115546                                                                  | 1.b      |
| Threats    | CVE-2025-30043                                                                   | 1.b      |
| Threats    | CVE-2025-30053                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.h**

Source: ketch Published: 2026-10-24

A Five Eyes joint advisory warns of ongoing state-sponsored spear-phishing campaigns targeting energy, transport, and water sectors. The threat actors employ highly tailored lures, compromised legitimate domains, and advanced evasion techniques to infiltrate critical national infrastructure. Defenders are urged to enhance email authentication, segment OT/IT networks, and monitor for lateral movement indicators following initial compromise.

___________________________________


# **[Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/)**

**PIR: 1.e**

Source: ketch Published: 2026-10-24

Microsoft Security researchers dissect the Tycoon2FA adversary-in-the-middle phishing kit, revealing how threat actors bypass multi-factor authentication at scale. The analysis details the kit’s proxy architecture, credential harvesting mechanisms, and infrastructure evasion tactics. IT defenders can leverage these insights to harden identity perimeters, deploy adaptive MFA policies, and detect real-time session hijacking attempts targeting enterprise accounts.

___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.a**

Source: ketch Published: 2026-10-24

This report maps the underground infrastructure supporting large-scale phishing operations, including domain generation algorithms, bulletproof hosting providers, and traffic routing techniques. Security teams gain actionable intelligence on infrastructure indicators, takedown strategies, and network-level detection rules to disrupt phishing campaigns before they reach end users.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.f**

Source: ketch Published: 2026-10-24

Microsoft Security exposes the EvilTokens toolkit, a modular framework designed to automate device code phishing and token theft. The breakdown covers its command-and-control structure, token persistence methods, and abuse of Microsoft Graph APIs. Infrastructure teams can use these findings to tune identity protection alerts, revoke compromised tokens, and enforce conditional access restrictions.

___________________________________


# **[Operation HookedWing: Four-Year Phishing Campaign Hits 500+ Organizations in Aviation, Critical Infrastructure, and Government](https://cybersecurityjournal.ca/techtalk/84066-operation-hookedwing-phishing-aviation-critical-infrastructure-2026-05-11/)**

**PIR: 1.i**

Source: ketch Published: 2026-10-24

SecurityWeek details Operation HookedWing, a persistent credential-harvesting campaign active since 2022 that has compromised over 500 organizations across aviation and critical infrastructure. The report outlines the attackers’ infrastructure rotation, domain spoofing tactics, and post-compromise data exfiltration. Infrastructure defenders can apply the provided IOCs, strengthen email filtering, and audit third-party access to mitigate similar long-term threats.

___________________________________


# **[Talos: Attackers Refine Phishing Playbook To Target Critical Infrastructure](https://securityledger.com/2026/07/talos-attackers-refine-phishing-playbook-to-target-critical-infrastructure/)**

**PIR: 1.i**

Source: ketch Published: 2026-10-24

Cisco Talos reports that threat actors are increasingly abusing trusted cloud services and legitimate SaaS platforms to launch phishing campaigns against healthcare, local government, and critical infrastructure. The analysis highlights infrastructure pivoting, domain fronting, and supply chain email compromises. Defenders should implement strict email security policies, monitor for anomalous cloud API usage, and prioritize identity-centric detection controls.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.f**

Source: ketch Published: 2026-10-24

Researchers analyze a sophisticated campaign leveraging generative AI to craft highly convincing device code phishing lures. The attack bypasses traditional email filters by targeting OAuth consent flows, tricking users into authorizing malicious applications. Defenders are advised to monitor for anomalous OAuth grants, restrict device code usage, and implement AI-detection heuristics in email gateways.

___________________________________


# **[Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts](https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts)**

**PIR: 1.f**

Source: ketch Published: 2026-10-24

Level Blue SpiderLabs introduces Wazza, an emerging device code phishing kit specifically engineered to compromise Microsoft 365 tenants. The analysis details its deployment workflow, credential exfiltration endpoints, and evasion of standard MFA prompts. IT administrators should review OAuth application permissions, monitor for suspicious device code sign-ins, and update detection signatures to block Wazza infrastructure.

___________________________________


# **[CVE-2026-115547](https://nvd.nist.gov/vuln/detail/CVE-2026-115547)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-23

An input validation issue in the Okta Access Gateway (OAG) Admin Console allows the processing of specially formatted configuration values. An authenticated administrator can leverage this to execute system commands within the context of the OAG service account.

___________________________________


# **[CVE-2026-79977](https://nvd.nist.gov/vuln/detail/CVE-2026-79977)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-23

The WireGuard VPN service in subsys/net/lib/wireguard/wg.c updated the peer endpoint from a message it could not authenticate. In handle_transport_data(), when the 32-bit receiver index of an incoming transport-data message matched no session, the code both scheduled a new handshake and copied the datagram's source address into peer->endpoint with memcpy(&peer->endpoint, peer_addr, sizeof(peer->endpoint)). Because the receiver index is unknown, there is no key with which such a message could be 

___________________________________


# **[CVE-2026-115546](https://nvd.nist.gov/vuln/detail/CVE-2026-115546)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-23

Okta Access Gateway (OAG) does not validate the selected authentication source during sign-on. An authenticated user with an active session can modify the authentication source parameter, which may generate a SAML assertion granting access to the Admin Console.

___________________________________


# **[CVE-2025-30043](https://nvd.nist.gov/vuln/detail/CVE-2025-30043)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-23

CGM CLININET is vulnerable to Missing Authentication for Critical Function in the /DocManagment path. The endpoint is accessible without authentication, allowing an unauthenticated attacker in the adjacent network to retrieve the list of patient documents and download those documents. 


This issue was fixed in version 2026.MS3

___________________________________


# **[CVE-2025-30053](https://nvd.nist.gov/vuln/detail/CVE-2025-30053)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-23

The CGM CLININET application runs the cgm-updater process listening on an open network port without any authentication.




The vulnerability was confirmed to affect versions up to 2026.MS3 but later versions may also be vulnerable.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-114191 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114191)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-24

Finance/Government: Broken access control in a UPI payment gateway plugin enables unauthenticated access to transaction data, directly impacting regulated digital payment infrastructure.

*Deep dive: `TIER_2_CVE-2026-114191.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine