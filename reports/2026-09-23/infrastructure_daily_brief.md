# **Infrastructure Daily Brief: 2026-09-23**

**Infrastructure Daily Report TLP:GREEN Alert Id: cd15eb1d 2026-09-24 05:10:26**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-76183 (Tier 2)                                                          | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.i      |
| Threats    | Cloudflare participates in global operation to disrupt EvilTokens Phishing-as-a- | 1.d      |
| Threats    | The Alert Gap: Hunting an Undetected Device Code Phishing Compromise             | 1.i      |
| Threats    | Microsoft 365: Block Device Code Flow Against GhostCode                          | 1.i      |
| Threats    | Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI  | 1.g      |
| Threats    | Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK                      | 1.a      |
| Threats    | GhostCode attackers abuse device codes to take over Microsoft 365 accounts       | 1.j      |
| Threats    | Bypassing the Gatekeepers: How a Global Phishing Campaign Turns Google's Infrast | 1.f      |
| Threats    | CVE-2026-93952                                                                   | 3.k      |
| Threats    | CVE-2026-94127                                                                   | 3.k      |
| Threats    | CVE-2026-93616                                                                   | 3.k      |
| Threats    | CVE-2026-77244                                                                   | 1.b      |
| Threats    | CVE-2026-77254                                                                   | 1.b      |
| Threats    | CVE-2026-17635                                                                   | 1.b      |
| Threats    | CVE-2026-17643                                                                   | 1.b      |
| Threats    | CVE-2026-75791                                                                   | 1.b      |
| Threats    | CVE-2026-18074                                                                   | 1.b      |
| Threats    | CVE-2026-96445                                                                   | 1.b      |
| Threats    | CVE-2026-95503                                                                   | 1.b      |
| Threats    | CVE-2026-18124                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.i**

Source: ketch Published: 2026-09-23

Microsoft researchers dissect the EvilTokens Phishing-as-a-Service operation, detailing how attackers exploit the OAuth device code flow to bypass multi-factor authentication. The report provides infrastructure defenders with actionable telemetry, detection rules, and mitigation strategies to block malicious device code requests and protect Microsoft 365 environments from credential theft.

___________________________________


# **[Cloudflare participates in global operation to disrupt EvilTokens Phishing-as-a-Service | Cloudflare](https://www.cloudflare.com/threat-intelligence/research/report/cloudflare-participates-in-global-operation-to-disrupt-eviltokens-phishing-as-a-service/)**

**PIR: 1.d**

Source: ketch Published: 2026-09-23

Cloudflare details its role in a coordinated global takedown of the EvilTokens infrastructure. The analysis covers the network architecture, domain generation algorithms, and proxy techniques used by the service. Defenders gain insights into identifying and blocking associated C2 domains, understanding the economic model of modern phishing-as-a-service, and implementing DNS-layer defenses.

___________________________________


# **[The Alert Gap: Hunting an Undetected Device Code Phishing Compromise](https://packetstorm.news/news/view/43540)**

**PIR: 1.i**

Source: ketch Published: 2026-09-23

This technical deep-dive explores the detection blind spots surrounding device code phishing campaigns. The author demonstrates how standard SIEM rules often miss these attacks due to legitimate-looking authentication patterns. The article provides advanced hunting queries for Microsoft Sentinel and Splunk, focusing on token issuance anomalies, cross-tenant sign-in behaviors, and lateral movement indicators post-compromise.

___________________________________


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973)**

**PIR: 1.i**

Source: ketch Published: 2026-09-23

A practical guide for IT administrators on disabling or restricting the OAuth device code flow in Microsoft 365 to counter GhostCode attacks. The article provides step-by-step configuration instructions for Conditional Access policies and Azure AD app registration settings. It emphasizes the trade-offs between usability and security, helping defenders implement least-privilege access while neutralizing automated device code phishing vectors.

___________________________________


# **[Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI](https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing)**

**PIR: 1.g**

Source: ketch Published: 2026-09-23

Researchers link the GTG-20006 actor to Midnight Blizzard, detailing their use of AI to automate device code phishing at scale. The report analyzes how machine learning models generate highly convincing prompts and manage victim interactions without human intervention. Defenders gain insights into identifying AI-driven campaign patterns, monitoring for rapid token validation attempts, and updating behavioral analytics to catch automated identity theft.

___________________________________


# **[Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)**

**PIR: 1.a**

Source: ketch Published: 2026-09-23

CloudSEK tracks the BigBear 2.0 campaign leveraging Evilginx2 to conduct sophisticated reverse-proxy phishing attacks. The report outlines how the tool bypasses MFA by intercepting session cookies during legitimate login flows. Infrastructure teams receive guidance on detecting proxy-based authentication anomalies, monitoring for suspicious TLS certificates, and hardening identity providers against session hijacking.

___________________________________


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.j**

Source: ketch Published: 2026-09-23

Computerworld examines the GhostCode threat group's methodology for exploiting device code authentication to compromise enterprise Microsoft 365 accounts. The report highlights how attackers automate the phishing process to harvest valid tokens, bypassing traditional MFA. Infrastructure defenders are advised to monitor for unusual device code sign-ins, enforce strict Conditional Access rules, and deploy identity protection alerts.

___________________________________


# **[Bypassing the Gatekeepers: How a Global Phishing Campaign Turns Google's Infrastructure into a Trust Proxy](https://blog.knowbe4.com/bypassing-the-gatekeepers-how-a-global-phishing-campaign-turns-googles-infrastructure-into-a-trust-proxy)**

**PIR: 1.f**

Source: ketch Published: 2026-09-23

This analysis reveals how threat actors abuse legitimate Google services to host phishing pages, effectively using major cloud infrastructure as a trust proxy. The campaign evades traditional URL filtering by leveraging high-reputation domains. Defenders learn to implement advanced reputation scoring, monitor for anomalous subdomain usage, and adjust email security gateways to catch infrastructure-abuse phishing attempts.

___________________________________


# **[CVE-2026-93952](https://nvd.nist.gov/vuln/detail/CVE-2026-93952)**

**PIR: 3.k**

Source: vulners/duckdb Published: 2026-09-22

VeloCloud Orchestrator (VCO) on-prem has a security issue where this issue may allow a remote attacker to access privileged internal functionality and impact the VCO host. Successful exploitation may compromise the confidentiality, integrity, and availability of the orchestrator and data managed by the orchestrator.

Hosted, including Dedicated, versions of VCO were impacted and have already been patched.

___________________________________


# **[CVE-2026-94127](https://nvd.nist.gov/vuln/detail/CVE-2026-94127)**

**PIR: 3.k**

Source: vulners/duckdb Published: 2026-09-22

When a BIG-IP APM access policy and an OAuth profile is configured on a virtual server, specific malicious traffic can lead to Remote Code Execution (RCE).

Impact:
This vulnerability allows an unauthenticated attacker to perform remote code execution. The BIG-IP system in Appliance mode is also vulnerable. This is a data plane issue; there is no control plane exposure.

 


Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

___________________________________


# **[CVE-2026-93616](https://nvd.nist.gov/vuln/detail/CVE-2026-93616)**

**PIR: 3.k**

Source: vulners/duckdb Published: 2026-09-22

A directory traversal and file upload vulnerability allows an unauthenticated attacker to upload and execute arbitrary scripts on Check Point Management Server.

___________________________________


# **[CVE-2026-77244](https://nvd.nist.gov/vuln/detail/CVE-2026-77244)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-22

MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to 0.22.0, the HTTP transport accepts requests without a verified user identity and downstream fetcher construction falls back to the operator's globally configured Jira or Confluence credentials. A network client that can reach the MCP endpoint can invoke Atlassian tools as the operator, including read and write operations available to that account. The advisory traces the vulnerable input

___________________________________


# **[CVE-2026-77254](https://nvd.nist.gov/vuln/detail/CVE-2026-77254)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-22

MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to 0.22.0, requests to the HTTP MCP endpoint without a per-user identity are allowed to reach tool handlers, which then use globally configured Jira or Confluence credentials. A network caller can perform operations with the operator account's permissions unless the deployment has an independent authentication boundary. The advisory traces the vulnerable input and processing flow through st

___________________________________


# **[CVE-2026-17635](https://nvd.nist.gov/vuln/detail/CVE-2026-17635)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-22

IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a remote attacker to perform unauthorized actions due to improper configuration of HTTP method-based security constraints.

___________________________________


# **[CVE-2026-17643](https://nvd.nist.gov/vuln/detail/CVE-2026-17643)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-22

IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a local attacker to obtain sensitive information and perform unauthorized actions due to insufficiently protected credentials.

___________________________________


# **[CVE-2026-75791](https://nvd.nist.gov/vuln/detail/CVE-2026-75791)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-22

Zohocorp ManageEngine ADSelfService Plus versions before build 7001 are vulnerable to an authentication bypass vulnerability in the REST API.

___________________________________


# **[CVE-2026-18074](https://nvd.nist.gov/vuln/detail/CVE-2026-18074)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-22

IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a remote attacker to perform unauthorized actions due to improper authentication and missing authorization.

___________________________________


# **[CVE-2026-96445](https://nvd.nist.gov/vuln/detail/CVE-2026-96445)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-23

A flaw was found in the Conditional OTP authenticator of Keycloak, an identity and access management solution. The issue occurs when the system evaluates specific HTTP headers to determine if a one-time password (OTP) should be skipped, but fails to verify if those headers came from a trusted source. This could allow an attacker who already has a user's password to bypass the second-factor authentication by providing a specially crafted header in their request.

___________________________________


# **[CVE-2026-95503](https://nvd.nist.gov/vuln/detail/CVE-2026-95503)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-22

A flaw was found in the Kerberos federation provider of Keycloak, an open-source identity and access management solution. When Kerberos password authentication is used without SPNEGO, the system fails to verify the identity of the Key Distribution Center (KDC) by requesting a server ticket. This allows an attacker on the same network to spoof the KDC and bypass the authentication process, potentially gaining unauthorized access to user accounts.

___________________________________


# **[CVE-2026-18124](https://nvd.nist.gov/vuln/detail/CVE-2026-18124)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-22

IBM Financial Transaction Manager (FTM) for RedHat OpenShift could allow a local attacker to obtain sensitive information due to insufficiently protected credentials.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-76183 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76183)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-23

Critical authentication bypass in Apache Tomcat, a foundational web server explicitly noted to support DPI ecosystems and public-facing enterprise services.

*Deep dive: `TIER_2_CVE-2026-76183.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine