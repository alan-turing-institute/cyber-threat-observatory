# **Infrastructure Daily Brief: 2026-10-15**

**Infrastructure Daily Report TLP:GREEN Alert Id: acb3d464 2026-10-22 01:01:03**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-102946 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111347 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111357 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-99999 (Tier 1)                                                          | 3.k      |
| Cyber News | CVE-2026-101287 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-106700 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111214 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111217 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111225 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-18661 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-53582 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-79829 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-79834 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-93484 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-101306 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-103936 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109413 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-109855 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111216 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111220 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-111277 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-47786 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-57155 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-102461 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-55103 (Tier 2)                                                          | 3.k      |
| Threats    | Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target West | 1.j.3    |
| Threats    | SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale     | 1.b      |
| Threats    | Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government A | 1.a      |
| Threats    | Capacity Enhancement Guide: Counter-Phishing Recommendations for Federal Agencie | 1.d      |
| Threats    | CVE-2026-84731                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Russian hacker group Laundry Bear exploits Zimbra zero-click flaw to target Western government, critical infrastructure](https://industrialcyber.co/cisa/russian-hacker-group-laundry-bear-exploits-zimbra-zero-click-flaw-to-target-western-government-critical-infrastructure)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-15

Russian threat group Laundry Bear is exploiting a critical zero-click vulnerability in Zimbra collaboration suites to infiltrate Western government and critical infrastructure networks. The exploit allows remote code execution without user interaction, bypassing traditional email security controls. Defenders should immediately patch Zimbra instances, isolate affected mail servers, and deploy network detection rules for known C2 traffic patterns.

___________________________________


# **[SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale](https://intel.breakglass.tech/post/sidewinder-mhil-zeabur)**

**PIR: 1.b**

Source: ketch Published: 2026-10-15

The SideWinder APT group has escalated its operations by abusing Platform-as-a-Service environments to host credential harvesting infrastructure at scale. By leveraging legitimate cloud services, attackers evade traditional blocklists and deploy highly convincing login pages. Infrastructure teams must implement strict egress filtering, monitor for unauthorized PaaS deployments, and deploy conditional access policies to detect compromised credentials.

___________________________________


# **[Three Active Microsoft 365 Phishing Campaigns Targeting Schools and Government Agencies](https://forsyteit.com/three-active-microsoft-365-phishing-campaigns-targeting-schools-and-government-agencies)**

**PIR: 1.a**

Source: ketch Published: 2026-10-15

Threat actors are actively deploying sophisticated phishing campaigns leveraging Microsoft 365 infrastructure to compromise educational and government networks. These campaigns utilize credential harvesting portals, malicious document attachments, and impersonation tactics to bypass standard email filters. IT defenders should monitor for anomalous sign-in locations, enforce MFA, and review shared mailbox permissions to mitigate lateral movement risks.

___________________________________


# **[Capacity Enhancement Guide: Counter-Phishing Recommendations for Federal Agencies](https://cisa.gov/sites/default/files/publications/Capacity_Enhancement_Guide-Counter-Phishing_Recommendations_for_Federal_Agencies.pdf)**

**PIR: 1.d**

Source: ketch Published: 2026-10-15

This CISA publication provides actionable counter-phishing strategies tailored for federal IT environments. It outlines best practices for email authentication enforcement, security awareness training, and incident response workflows. Agencies are advised to implement DMARC monitoring, restrict external forwarding, and establish rapid credential reset protocols to minimize the impact of successful phishing attempts across critical infrastructure systems.

___________________________________


# **[CVE-2026-84731](https://nvd.nist.gov/vuln/detail/CVE-2026-84731)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-15

An unauthenticated remote attacker can bypass authentication and gain full access to administrative API endpoints in Nutanix Prism Element by including a crafted internal management HTTP header. The vulnerability is caused by a misconfiguration in the application's authentication filters.



Consequently, the server responds with a Set-Cookie header containing a valid JSESSIONID. This session cookie decodes to a JSON Web Token (JWT) granting maximum cluster administrative privileges. Successful 

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-102946 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102946)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Critical authentication bypass in a core JWT/JWS library directly impacts Digital Identity infrastructure, OAuth/OIDC flows, and session management systems.

*Deep dive: `TIER_2_CVE-2026-102946.md`*

___________________________________


# **[CVE-2026-111347 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111347)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Directly compromises foundational LDAP/IdAM infrastructure via hardcoded keys and unauthenticated endpoints, enabling enterprise-wide credential theft and account takeover.

*Deep dive: `TIER_2_CVE-2026-111347.md`*

___________________________________


# **[CVE-2026-111357 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111357)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

TIER 2 local privilege escalation in Ivanti Connect Secure VPN/IdAM appliances, actively exploited in the wild to achieve root access and compromise remote identity and session management infrastructure.

*Deep dive: `TIER_2_CVE-2026-111357.md`*

___________________________________


# **[CVE-2026-99999 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2026-99999)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Foundational Linux kernel flaw enabling VM/container escape and host root compromise, directly impacting the cloud and virtualization infrastructure underpinning all DPI sectors.

*Deep dive: `TIER_1_CVE-2026-99999.md`*

___________________________________


# **[CVE-2026-101287 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101287)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

TIER 2 authentication bypass in a public-facing institutional platform directly compromises session integrity and JWT issuance, impacting Digital Identity and Government sectors.

*Deep dive: `TIER_2_CVE-2026-101287.md`*

___________________________________


# **[CVE-2026-106700 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-106700)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Directly compromises IAM functions in enterprise backend frameworks, enabling authenticated users to hijack arbitrary accounts and escalate to full administrative control (Digital Identity).

*Deep dive: `TIER_2_CVE-2026-106700.md`*

___________________________________


# **[CVE-2026-111214 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111214)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

TIER 2 authenticated root RCE in pfSense CE, a foundational firewall platform explicitly deployed across government, enterprise, and ISP network perimeters.

*Deep dive: `TIER_2_CVE-2026-111214.md`*

___________________________________


# **[CVE-2026-111217 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111217)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Core networking infrastructure (pfSense firewall) widely deployed in government and enterprise environments; root RCE impacts perimeter security and service availability.

*Deep dive: `TIER_2_CVE-2026-111217.md`*

___________________________________


# **[CVE-2026-111225 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111225)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Foundational edge firewall/VPN gateway deployed across government, finance, and healthcare sectors; RCE impacts perimeter security and remote access.

*Deep dive: `TIER_2_CVE-2026-111225.md`*

___________________________________


# **[CVE-2026-18661 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18661)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Critical authentication bypass in Eclipse Jetty, a foundational web server explicitly supporting government, finance, and healthcare digital services.

*Deep dive: `TIER_2_CVE-2026-18661.md`*

___________________________________


# **[CVE-2026-53582 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-53582)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

TIER 2 XPath injection in OPNsense firewall certificate management enables extraction of root hashes and VPN keys, impacting government and finance perimeter security infrastructure.

*Deep dive: `TIER_2_CVE-2026-53582.md`*

___________________________________


# **[CVE-2026-79829 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79829)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Unauthenticated remote DoS in HPE NonStop HTTP WebServer, a mission-critical platform widely deployed in finance, government, and utilities for high-availability public services.

*Deep dive: `TIER_2_CVE-2026-79829.md`*

___________________________________


# **[CVE-2026-79834 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79834)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Unauthenticated RCE in HPE NonStop SQLCAT, a backend database component widely deployed in core banking, payment switching, and critical government infrastructure.

*Deep dive: `TIER_2_CVE-2026-79834.md`*

___________________________________


# **[CVE-2026-93484 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-93484)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

High-severity SQLi in Znuny ITSM platform, widely deployed by government agencies and public institutions for internal service management and citizen-facing portals.

*Deep dive: `TIER_2_CVE-2026-93484.md`*

___________________________________


# **[CVE-2026-101306 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-101306)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Tier 2 FreeBSD kernel jail escape impacts foundational hosting/networking infrastructure that underpins government and finance digital services.

*Deep dive: `TIER_2_CVE-2026-101306.md`*

___________________________________


# **[CVE-2026-103936 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103936)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Foundational P2P middleware underpinning decentralized finance and identity networks faces trivial unauthenticated DoS, threatening availability of public-facing blockchain validators and IPFS gateways.

*Deep dive: `TIER_2_CVE-2026-103936.md`*

___________________________________


# **[CVE-2026-109413 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109413)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

General-purpose web framework widely deployed in government portals and healthcare patient systems; unauthenticated DoS risks service availability for public digital services.

*Deep dive: `TIER_2_CVE-2026-109413.md`*

___________________________________


# **[CVE-2026-109855 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109855)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Core Node.js HTTP client library (undici) DoS impacts availability of government, healthcare, and financial web services relying on Node.js backends.

*Deep dive: `TIER_2_CVE-2026-109855.md`*

___________________________________


# **[CVE-2026-111216 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111216)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Tier 2 root RCE in pfSense CE edge firewall, critical general infrastructure deployed across regulated and public-sector network perimeters.

*Deep dive: `TIER_2_CVE-2026-111216.md`*

___________________________________


# **[CVE-2026-111220 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111220)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Tier 2 root RCE in pfSense CE firewalls, a foundational perimeter security product widely deployed across government, finance, and healthcare networks.

*Deep dive: `TIER_2_CVE-2026-111220.md`*

___________________________________


# **[CVE-2026-111277 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111277)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Unauthenticated exposure of guest PII and transactional data on public-facing e-commerce platforms impacts regulated commerce and financial services infrastructure.

*Deep dive: `TIER_2_CVE-2026-111277.md`*

___________________________________


# **[CVE-2026-47786 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-47786)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Pre-auth RCE in widely deployed QNAP NAS storage infrastructure explicitly used across government, healthcare, and finance sectors.

*Deep dive: `TIER_2_CVE-2026-47786.md`*

___________________________________


# **[CVE-2026-57155 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-57155)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

TIER 2 authenticated root RCE in OPNsense edge firewalls, a foundational networking stack securing perimeter access for regulated and public digital services.

*Deep dive: `TIER_2_CVE-2026-57155.md`*

___________________________________


# **[CVE-2026-102461 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102461)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Tier 2 unauthenticated DoS in Eclipse Vert.x JSON schema validation, a foundational framework underpinning internet-facing APIs and microservices for finance and government digital services.

*Deep dive: `TIER_2_CVE-2026-102461.md`*

___________________________________


# **[CVE-2026-55103 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55103)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-15

Unauthenticated authorization bypass in a widely deployed open-source forum engine used for civic and government public engagement, risking content manipulation and disinformation on federated community platforms.

*Deep dive: `TIER_2_CVE-2026-55103.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine