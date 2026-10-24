# **Infrastructure Daily Brief: 2026-10-23**

**Infrastructure Daily Report TLP:GREEN Alert Id: 829c553c 2026-10-24 10:26:01**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-57209 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-89320 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-105482 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-10632 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-115937 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-46651 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-46652 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-55459 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-57210 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-58202 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-65824 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-55457 (Tier 2)                                                          | 3.k      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.h      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.e      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.g      |
| Threats    | Storm-2372 conducts device code phishing campaign                                | 1.j.3    |
| Threats    | Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vish | 1.a      |
| Threats    | ShinyHunters Cluster A Phishing Infrastructure on Mevspace (Doko's Panel, vishin | 1.i      |
| Threats    | SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale     | 1.j.3    |
| Threats    | n8n Weaponized for Phishing and Device Fingerprinting                            | 1.d      |
| Threats    | CVE-2026-83938                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.h**

Source: ketch Published: 2026-10-23

Device code phishing has emerged as a primary vector for identity takeover, exploiting OAuth 2.0 device authorization flows to bypass traditional MFA. Threat actors deploy automated toolkits and phishing-as-a-service platforms to harvest valid tokens directly from legitimate authentication endpoints. Infrastructure defenders must monitor for anomalous device code requests, implement conditional access policies, and restrict device flow usage to approved applications.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.e**

Source: ketch Published: 2026-10-23

This Microsoft analysis reveals how AI-driven automation scales device code phishing by generating live authentication codes on demand and maintaining persistent post-compromise access. The campaign demonstrates end-to-end workflow automation that adapts to victim behavior and evades static detection rules. Defenders should deploy behavioral analytics for identity access patterns, restrict AI-assisted automation in authentication flows, and enforce token lifetime limits.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.g**

Source: ketch Published: 2026-10-23

Threat actors increasingly leverage cloud-native services and serverless architectures to host phishing infrastructure, evading traditional perimeter defenses. This report details how attackers abuse legitimate cloud providers to deploy dynamic phishing pages, rotate domains rapidly, and maintain persistent access. Infrastructure defenders must implement cloud workload protection, monitor for anomalous API usage, and enforce strict egress controls to disrupt these campaigns.

___________________________________


# **[Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-23

The Storm-2372 APT group has conducted a sustained device code phishing campaign since August 2024, mimicking messaging platforms like WhatsApp, Signal, and Teams to harvest credentials. Their infrastructure leverages compromised legitimate domains and dynamic content rendering to evade URL filtering. Infrastructure teams must implement deep packet inspection for OAuth token exchanges, monitor for APT-associated infrastructure, and enforce strict conditional access rules.

___________________________________


# **[Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM](https://intel.threadlinqs.com/threat/TL-2026-3778)**

**PIR: 1.a**

Source: ketch Published: 2026-10-23

Attackers are impersonating IT helpdesk personnel within Microsoft Teams to conduct targeted phishing, vishing, and unauthorized remote access via screen sharing and RMM tools. By exploiting trust in internal support channels, threat actors bypass email filters and extract credentials or deploy malware. Defenders should enforce strict external chat policies, require multi-factor authentication for RMM access, and train staff to verify helpdesk requests through out-of-band channels.

___________________________________


# **[ShinyHunters Cluster A Phishing Infrastructure on Mevspace (Doko's Panel, vishing + AiTM credential capture)](https://intel.threadlinqs.com/threat/TL-2026-3892)**

**PIR: 1.i**

Source: ketch Published: 2026-10-23

The ShinyHunters cluster operates a sophisticated phishing-as-a-service ecosystem hosted on Mevspace, utilizing Doko's Panel for rapid campaign deployment. This infrastructure supports vishing operations and advanced AI-powered man-in-the-middle credential capture. Infrastructure teams must block known PhaaS domains, implement DNS sinkholing for suspicious TLDs, and deploy real-time threat intelligence feeds to disrupt shared criminal infrastructure.

___________________________________


# **[SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale](https://intel.breakglass.tech/post/sidewinder-mhil-zeabur)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-23

SideWinder APT exploits PhaaS platforms and cloud hosting providers to execute large-scale credential harvesting operations targeting enterprise identity systems. The campaign abuses legitimate PaaS environments to host phishing portals, rotate infrastructure rapidly, and exfiltrate authentication tokens. Defenders should monitor for anomalous cloud resource provisioning, implement zero-trust identity validation, and integrate threat intelligence to block APT-associated hosting clusters.

___________________________________


# **[n8n Weaponized for Phishing and Device Fingerprinting](https://labs.cloudsecurityalliance.org/research/csa-research-note-n8n-ai-workflow-phishing-20260416-csa-styl)**

**PIR: 1.d**

Source: ketch Published: 2026-10-23

Open-source automation tools like n8n are being repurposed by threat actors to orchestrate phishing campaigns and perform device fingerprinting at scale. By chaining legitimate workflow nodes, attackers automate credential harvesting, session token extraction, and victim profiling. Defenders should audit third-party automation deployments, restrict outbound connections from workflow engines, and monitor for unauthorized API integrations in identity management systems.

___________________________________


# **[CVE-2026-83938](https://nvd.nist.gov/vuln/detail/CVE-2026-83938)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-22

Missing authentication for critical function in Azure Kubernetes Configuration Service allows an unauthorized attacker to elevate privileges over a network.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-57209 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-57209)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Directly impacts Digital Identity infrastructure by compromising an Identity Aware Proxy (IAP), allowing attackers to bypass IP-based access controls and undermine authentication/authorization boundaries.

*Deep dive: `TIER_2_CVE-2026-57209.md`*

___________________________________


# **[CVE-2026-89320 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-89320)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Breaks JWE integrity in a widely used Go IdAM library, enabling token manipulation that bypasses authorization in digital identity, finance, and government portals.

*Deep dive: `TIER_2_CVE-2026-89320.md`*

___________________________________


# **[CVE-2026-105482 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105482)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Foundational Node.js runtime flaw enabling SSRF bypass in public-facing APIs and microservices that underpin cross-sector digital public services.

*Deep dive: `TIER_2_CVE-2026-105482.md`*

___________________________________


# **[CVE-2026-10632 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-10632)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Impacts session integrity and account boundaries in Zimbra, an enterprise email platform widely deployed across government and financial sectors for secure communications and digital identity workflows.

*Deep dive: `TIER_2_CVE-2026-10632.md`*

___________________________________


# **[CVE-2026-115937 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-115937)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Finance sector: unauthenticated webhook manipulation allows forged payment confirmations and direct financial loss for e-commerce merchants.

*Deep dive: `TIER_2_CVE-2026-115937.md`*

___________________________________


# **[CVE-2026-46651 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-46651)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Unauthenticated SSRF and potential RCE in Goobi viewer, a public-facing digital library platform widely deployed by national libraries and cultural heritage institutions (Government sector).

*Deep dive: `TIER_2_CVE-2026-46651.md`*

___________________________________


# **[CVE-2026-46652 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-46652)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Unauthenticated RCE in Goobi viewer, a public-facing web portal widely deployed by national libraries, state museums, and public archives (Government/Cultural Heritage sector).

*Deep dive: `TIER_2_CVE-2026-46652.md`*

___________________________________


# **[CVE-2026-55459 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55459)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Directly impacts OIDC/JWT authentication flows in public-sector digital libraries and national archives, enabling unauthorized access to citizen-facing cultural heritage platforms.

*Deep dive: `TIER_2_CVE-2026-55459.md`*

___________________________________


# **[CVE-2026-57210 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-57210)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Digital Identity sector: IP spoofing in Heimdall IAP bypasses access control rules, impacting cloud-native authentication and authorization pipelines.

*Deep dive: `TIER_2_CVE-2026-57210.md`*

___________________________________


# **[CVE-2026-58202 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-58202)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Impacts Healthcare and Digital Identity sectors by enabling unauthenticated account takeover and passkey hijacking in public-facing clinic/hospital scheduling platforms.

*Deep dive: `TIER_2_CVE-2026-58202.md`*

___________________________________


# **[CVE-2026-65824 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-65824)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Authentication bypass in a public-facing healthcare appointment booking system compromises staff/admin accounts and patient scheduling data, impacting Healthcare and Digital Identity sectors.

*Deep dive: `TIER_2_CVE-2026-65824.md`*

___________________________________


# **[CVE-2026-55457 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-55457)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-23

Impacts public-facing digital library and archive portals frequently deployed by government and cultural heritage institutions, risking unauthorized access to civic digital collections.

*Deep dive: `TIER_2_CVE-2026-55457.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine