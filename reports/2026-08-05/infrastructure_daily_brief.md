# **Infrastructure Daily Brief: 2026-08-05**

**Infrastructure Daily Report TLP:GREEN Alert Id: 792057fd 2026-08-06 15:16:11**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-15572 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-15573 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-16102 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-16442 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-16443 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-18854 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-18969 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-18970 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20263 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20272 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20301 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20310 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-44945 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-55707 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-18859 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20268 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20270 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j.3    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j.3    |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.j.3    |
| Threats    | New widespread EvilTokens kit: device code phishing as-a-service                 | 1.a      |
| Threats    | Inside Kali365, a Device Code Phishing Ecosystem | Huntress                      | 1.a      |
| Threats    | The Shadow Campaigns: Uncovering Global Espionage                                | 1.b      |
| Threats    | Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and | 1.b      |
| Threats    | CVE-2026-63455                                                                   | 1.b      |
| Threats    | CVE-2026-63456                                                                   | 1.b      |
| Threats    | CVE-2026-9192                                                                    | 1.b      |
| Threats    | CVE-2026-71289                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-05

Microsoft details an AI-driven device code phishing campaign that automates authentication code generation. Attackers bypass traditional defenses by dynamically creating valid codes, enabling persistent account access. Defenders should monitor for anomalous device code requests, enforce conditional access policies, and deploy AI-aware detection rules to mitigate this evolving identity threat.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-05

Proofpoint analyzes how device code phishing has matured into a primary vector for identity takeover. Threat actors leverage automated infrastructure to harvest credentials and session tokens at scale. Infrastructure teams must implement strict MFA policies, monitor for suspicious OAuth consent grants, and educate users on recognizing dynamic code prompts to prevent account compromise.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-05

Securelist examines phishing attacks exploiting the Microsoft identity platform, showing why URL inspection alone is insufficient. Attackers mimic legitimate Microsoft login flows to steal credentials and tokens. Defenders should implement application allow-listing, monitor for non-browser authentication methods, and deploy identity protection solutions that detect anomalous consent and device code usage.

___________________________________


# **[New widespread EvilTokens kit: device code phishing as-a-service](https://blog.sekoia.io/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1/)**

**PIR: 1.a**

Source: ketch Published: 2026-08-05

Sekoia.io uncovers the EvilTokens kit, a phishing-as-a-service platform specializing in device code attacks. The toolkit enables low-skill actors to deploy sophisticated identity theft campaigns rapidly. Defenders should block known malicious domains, analyze OAuth token lifecycles, and integrate threat intelligence feeds to detect EvilTokens infrastructure early.

___________________________________


# **[Inside Kali365, a Device Code Phishing Ecosystem | Huntress](https://www.huntress.com/blog/kali365-device-code-phishing-kit)**

**PIR: 1.a**

Source: ketch Published: 2026-08-05

Huntress dissects the Kali365 ecosystem, revealing a coordinated network of device code phishing kits. The campaign demonstrates advanced operational security and rapid infrastructure rotation. IT defenders must prioritize log analysis for unusual authentication patterns, enforce zero-trust identity controls, and collaborate with threat intel sharing communities to disrupt the ecosystem.

___________________________________


# **[The Shadow Campaigns: Uncovering Global Espionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)**

**PIR: 1.b**

Source: ketch Published: 2026-08-05

Unit 42 reveals Shadow Campaigns, a global espionage operation leveraging sophisticated spearphishing and supply chain compromises. The threat actor targets high-value infrastructure with custom malware and persistent access techniques. Defenders must enhance email security gateways, monitor for lateral movement indicators, and enforce strict network segmentation to mitigate advanced persistent threats.

___________________________________


# **[Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a)**

**PIR: 1.b**

Source: ketch Published: 2026-08-05

CISA warns of a targeted spearphishing campaign against government and international organizations. The operation uses highly tailored lures and credential harvesting sites to gain initial access. Infrastructure teams should prioritize user awareness training, implement advanced email filtering, and establish rapid incident response playbooks for identity-based breaches.

___________________________________


# **[CVE-2026-63455](https://nvd.nist.gov/vuln/detail/CVE-2026-63455)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-04

Multiple vulnerabilities in the REST API interface of HPE Networking SD-WAN Orchestrator could allow an unauthenticated remote attacker to bypass web authentication mechanisms and access system functions. Successful exploitation could allow an attacker to view and modify potentially sensitive information on the target system.

___________________________________


# **[CVE-2026-63456](https://nvd.nist.gov/vuln/detail/CVE-2026-63456)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-04

Multiple vulnerabilities in the REST API interface of HPE Networking SD-WAN Orchestrator could allow an unauthenticated remote attacker to bypass web authentication mechanisms and access system functions. Successful exploitation could allow an attacker to view and modify potentially sensitive information on the target system.

___________________________________


# **[CVE-2026-9192](https://nvd.nist.gov/vuln/detail/CVE-2026-9192)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-05

An authentication bypass vulnerability in the ODBC App Server of Progress MarkLogic Server before 11.3.6 and 12.0.3 allows an unauthenticated remote attacker to bypass password verification and execute queries with the privileges of any named user known to the server, including administrators.

___________________________________


# **[CVE-2026-71289](https://nvd.nist.gov/vuln/detail/CVE-2026-71289)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-05

The NASA-AMMOS Asynchronous Network Management System (ANMS) reference implementation's default docker-compose.yml publishes the amp-manager service's REST API directly to the host network interface (port 8089, e.g. "${ION_MGR_PORT:-8089}:8089/tcp") with cap_add: NET_ADMIN, NET_RAW, SYS_NICE, bypassing the CAM (Configuration and Access Manager) gateway that is otherwise the system's sole authentication boundary. The underlying REST server, implemented with CivetWeb in JHUAPL/dtnma-tools (src/ref

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-15572 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-15572)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Core IdAM platform (Keycloak) vulnerability allowing privilege escalation to realm admin via DCR policy bypass, directly impacting digital identity and access management infrastructure.

*Deep dive: `TIER_2_CVE-2026-15572.md`*

___________________________________


# **[CVE-2026-15573 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-15573)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Keycloak authorization bypass impacts core IdAM/SSO controls, directly affecting Digital Identity infrastructure for government, healthcare, and finance sectors.

*Deep dive: `TIER_2_CVE-2026-15573.md`*

___________________________________


# **[CVE-2026-16102 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-16102)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

TIER 2 authorization bypass in Keycloak's Dynamic Client Registration enables standard users to forge admin roles, directly impacting Digital Identity infrastructure and enterprise IdP deployments.

*Deep dive: `TIER_2_CVE-2026-16102.md`*

___________________________________


# **[CVE-2026-16442 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-16442)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Directly impacts core Digital Identity infrastructure by enabling authentication bypass and account takeover in Keycloak's SAML federation workflows.

*Deep dive: `TIER_2_CVE-2026-16442.md`*

___________________________________


# **[CVE-2026-16443 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-16443)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Directly impacts the Digital Identity sector by bypassing SAML signature validation in Keycloak, enabling account takeover in federated authentication flows.

*Deep dive: `TIER_2_CVE-2026-16443.md`*

___________________________________


# **[CVE-2026-18854 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18854)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Unauthenticated SQLi in PDM software widely deployed across China's defense industrial base and state-linked manufacturing, posing government sector and supply chain risks.

*Deep dive: `TIER_2_CVE-2026-18854.md`*

___________________________________


# **[CVE-2026-18969 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18969)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

TIER 2 unauthenticated RCE in a government command and dispatch platform used by public security and emergency management agencies.

*Deep dive: `TIER_2_CVE-2026-18969.md`*

___________________________________


# **[CVE-2026-18970 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18970)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Unauthenticated SQLi in a government command and dispatch platform used for public security and emergency response.

*Deep dive: `TIER_2_CVE-2026-18970.md`*

___________________________________


# **[CVE-2026-20263 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20263)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Foundational Cisco IOS XE networking software underpins government and regulated sector infrastructure, making remote DoS a high-availability risk for public digital services.

*Deep dive: `TIER_2_CVE-2026-20263.md`*

___________________________________


# **[CVE-2026-20272 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20272)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Critical injection flaws in Cisco IOS XE network OS (CVSS 9.8) threaten foundational connectivity for government, finance, healthcare, and digital identity infrastructure.

*Deep dive: `TIER_2_CVE-2026-20272.md`*

___________________________________


# **[CVE-2026-20301 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20301)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Foundational Cisco routing/switching infrastructure underpins government and national digital services; DoS risk to core network nodes warrants attention despite disabled-by-default feature.

*Deep dive: `TIER_2_CVE-2026-20301.md`*

___________________________________


# **[CVE-2026-20310 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20310)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Critical internal management plane flaw in foundational SD-WAN infrastructure supporting FedRAMP/government and enterprise deployments; requires patching due to zero workarounds.

*Deep dive: `TIER_2_CVE-2026-20310.md`*

___________________________________


# **[CVE-2026-44945 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-44945)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

General infrastructure Kubernetes orchestrator explicitly tied to Government and Finance deployments; privilege escalation grants full control plane and secrets access across regulated environments.

*Deep dive: `TIER_2_CVE-2026-44945.md`*

___________________________________


# **[CVE-2026-55707 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55707)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

TIER 2 cross-tenant authorization bypass in OpenStack Neutron, a foundational cloud networking stack explicitly noted for government and enterprise deployments.

*Deep dive: `TIER_2_CVE-2026-55707.md`*

___________________________________


# **[CVE-2026-18859 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18859)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Unauthenticated SQLi in a government/enterprise DLP platform, risking internal data breaches in regulated networks.

*Deep dive: `TIER_2_CVE-2026-18859.md`*

___________________________________


# **[CVE-2026-20268 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20268)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Foundational enterprise networking stack (Cisco IOS XE) underpins government, healthcare, and financial infrastructure, requiring prompt patching due to high severity and lack of workarounds.

*Deep dive: `TIER_2_CVE-2026-20268.md`*

___________________________________


# **[CVE-2026-20270 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20270)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-05

Foundational networking OS for edge routers and firewalls that underpins connectivity for regulated and public digital services.

*Deep dive: `TIER_2_CVE-2026-20270.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine