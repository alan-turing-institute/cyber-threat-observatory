# **Infrastructure Daily Brief: 2026-08-07**

**Infrastructure Daily Report TLP:GREEN Alert Id: 913b79fc 2026-08-08 10:47:30**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2022-4995 (Tier 1)                                                           | 3.k      |
| Cyber News | CVE-2026-54203 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-62295 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-47661 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-52878 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54200 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54202 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54210 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54213 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54204 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-54209 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-58262 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j.3    |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.j.3    |
| Threats    | New widespread EvilTokens kit: device code phishing as-a-service                 | 1.j.3    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j.3    |
| Threats    | Storm-2372 conducts device code phishing campaign                                | 1.j.3    |
| Threats    | UK and partners expose Russian state-supported actors for new zero-click phishin | 1.a      |
| Threats    | The Shadow Campaigns: Uncovering Global Espionage                                | 1.a      |
| Threats    | New APT group breached gov and critical infrastructure orgs in 37 countries      | 1.a      |
| Threats    | CVE-2026-50481                                                                   | 1.b      |
| Threats    | CVE-2026-59115                                                                   | 1.b      |
| Threats    | CVE-2026-47660                                                                   | 1.b      |
| Threats    | CVE-2026-47662                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-07

Threat actors are leveraging AI and end-to-end automation to scale device code phishing attacks, bypassing traditional email filters. This campaign generates live authentication codes on demand, significantly increasing success rates and enabling sustained post-compromise access. Infrastructure defenders must monitor OAuth consent grants and implement conditional access policies to mitigate these evolving identity takeover tactics.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-07

Attackers are exploiting legitimate Microsoft identity endpoints to conduct sophisticated phishing campaigns that evade standard URL-based detection. By leveraging authorized OAuth flows, threat actors trick users into granting malicious tokens, rendering traditional link inspection ineffective. Defenders should prioritize monitoring for anomalous token issuance, restrict third-party app permissions, and deploy identity-aware network controls to block unauthorized access.

___________________________________


# **[New widespread EvilTokens kit: device code phishing as-a-service](https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-07

The EvilTokens toolkit has emerged as a commercialized device code phishing-as-a-service platform, lowering the barrier for credential theft. It automates the generation of malicious OAuth consent pages and token harvesting, targeting enterprise environments. Security teams must audit delegated permissions, enforce multi-factor authentication with phishing-resistant methods, and monitor for suspicious device code requests in identity logs.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-07

Device code phishing represents a significant shift in identity compromise tactics, moving beyond traditional credential harvesting to direct token theft. Attackers exploit legitimate authentication flows to bypass MFA and gain persistent access to cloud environments. Infrastructure defenders should implement strict OAuth consent policies, monitor for unusual device code usage patterns, and educate users on recognizing legitimate verification prompts.

___________________________________


# **[Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-07

The Storm-2372 threat group has adopted device code phishing to target government and enterprise networks, leveraging automated infrastructure to distribute malicious OAuth prompts. This campaign highlights the growing sophistication of state-aligned actors in exploiting identity platforms. Defenders must correlate identity telemetry with threat intelligence, restrict app consent workflows, and deploy behavioral analytics to detect anomalous authentication patterns.

___________________________________


# **[UK and partners expose Russian state-supported actors for new zero-click phishing campaign](https://www.ncsc.gov.uk/news/uk-and-partners-expose-russian-state-supported-actors-for-new-zero-click-phishing-campaign)**

**PIR: 1.a**

Source: ketch Published: 2026-08-07

Intelligence agencies have uncovered a zero-click phishing campaign orchestrated by Russian state-supported actors, exploiting vulnerabilities in messaging and identity services to compromise targets without user interaction. This technique bypasses traditional email security and user training defenses. Infrastructure teams should prioritize patching known vulnerabilities, segmenting critical identity systems, and monitoring for lateral movement indicators following silent compromises.

___________________________________


# **[The Shadow Campaigns: Uncovering Global Espionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)**

**PIR: 1.a**

Source: ketch Published: 2026-08-07

Unit 42 details a sprawling espionage operation utilizing highly targeted spearphishing emails to deploy custom malware across multiple sectors. The campaign leverages realistic document attachments and credential harvesting portals to establish initial access. Defenders should enhance email gateway filtering, deploy sandboxing for macro-enabled documents, and monitor for anomalous outbound connections indicative of command-and-control activity.

___________________________________


# **[New APT group breached gov and critical infrastructure orgs in 37 countries](https://www.csoonline.com/article/4128378/new-apt-group-breached-gov-and-critical-industrial-orgs-in-37-countries.html)**

**PIR: 1.a**

Source: ketch Published: 2026-08-07

A newly identified APT group has successfully breached government and critical infrastructure organizations across 37 nations using sophisticated spearphishing techniques. The attackers employ tailored lures and living-off-the-land binaries to evade detection. Infrastructure defenders must enforce least-privilege access, monitor for suspicious PowerShell execution, and implement robust identity governance to limit blast radius during breaches.

___________________________________


# **[CVE-2026-50481](https://nvd.nist.gov/vuln/detail/CVE-2026-50481)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-06

Modification of assumed-immutable data (maid) in Azure Active Directory allows an authorized attacker to elevate privileges over a network.

___________________________________


# **[CVE-2026-59115](https://nvd.nist.gov/vuln/detail/CVE-2026-59115)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-06

'.../...//' in Microsoft Entra Provisioning Service (SyncFabric) allows an authorized attacker to elevate privileges over a network.

___________________________________


# **[CVE-2026-47660](https://nvd.nist.gov/vuln/detail/CVE-2026-47660)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-07

Pathling is a set of tools that make it easier to use FHIR and clinical terminology within health data analytics. Prior to version 2.0.0 of Pathling Server, Pathling's bulk-submit operation allows an allowed submitter to supply an explicit `oauthMetadataUrl` parameter that is not validated against `pathling.bulkSubmit.allowableSources`. When present, the bulk-submit OAuth flow trusts metadata and the returned `token_endpoint` from the caller-chosen location, then builds outbound OAuth client aut

___________________________________


# **[CVE-2026-47662](https://nvd.nist.gov/vuln/detail/CVE-2026-47662)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-07

Pathling is a set of tools that make it easier to use FHIR and clinical terminology within health data analytics. Prior to version 2.0.0 of Pathling Server, Pathling's typed CRUD/search/batch FHIR surface allows an authenticated caller with only coarse operation authorities to act on attacker-chosen resource families because those entrypoints do not consistently enforce the documented per-resource `read` and `write` authorities. The documented authorization model requires an operation authority 

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2022-4995 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2022-4995)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Tier 1 unauthenticated RCE in Weaver E-cology OA platforms, extensively deployed across the Government sector for critical digital workflows and administrative data.

*Deep dive: `TIER_1_CVE-2022-4995.md`*

___________________________________


# **[CVE-2026-54203 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54203)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Impacts sovereign government communications and enterprise identity management in the DACH region via unauthenticated credential leakage in a widely deployed M365 alternative.

*Deep dive: `TIER_2_CVE-2026-54203.md`*

___________________________________


# **[CVE-2026-62295 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62295)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Impacts healthcare DPI by enabling DoS against HAPI FHIR servers, a foundational library for clinical data exchange and EHR interoperability.

*Deep dive: `TIER_2_CVE-2026-62295.md`*

___________________________________


# **[CVE-2026-47661 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-47661)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Tier 2 path traversal in FHIR analytics server Pathling enables unauthenticated exfiltration of patient records (PHI), directly impacting healthcare digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-47661.md`*

___________________________________


# **[CVE-2026-52878 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-52878)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Finance sector relevance: unauthenticated DoS against blockchain consensus nodes threatens decentralized payment channels and DeFi transaction processing.

*Deep dive: `TIER_2_CVE-2026-52878.md`*

___________________________________


# **[CVE-2026-54200 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54200)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Government sector: sovereign M365 alternative widely deployed across DACH public sector for official communications.

*Deep dive: `TIER_2_CVE-2026-54200.md`*

___________________________________


# **[CVE-2026-54202 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54202)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Path traversal in Tobit TeamDavid, a sovereign collaboration suite widely deployed by European government entities, enabling filesystem manipulation post-authentication.

*Deep dive: `TIER_2_CVE-2026-54202.md`*

___________________________________


# **[CVE-2026-54210 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54210)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Unauthenticated DoS in Tobit TeamDavid Webbox, a widely deployed on-premises collaboration suite for DACH government agencies and public sector entities.

*Deep dive: `TIER_2_CVE-2026-54210.md`*

___________________________________


# **[CVE-2026-54213 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54213)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Unauthenticated remote DoS on a widely deployed enterprise collaboration suite serving as a primary M365 alternative for DACH government and public sector organizations.

*Deep dive: `TIER_2_CVE-2026-54213.md`*

___________________________________


# **[CVE-2026-54204 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54204)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Unauthenticated SSRF in Tobit TeamDavid enables NetNTLM hash capture, impacting enterprise and public-sector collaboration deployments widely used in the DACH region.

*Deep dive: `TIER_2_CVE-2026-54204.md`*

___________________________________


# **[CVE-2026-54209 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54209)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Unauthenticated DoS in a widely deployed on-premises collaboration suite used by DACH-region government and municipal bodies for sovereign communications.

*Deep dive: `TIER_2_CVE-2026-54209.md`*

___________________________________


# **[CVE-2026-58262 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-58262)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-07

Finance: consensus bypass in Klever blockchain undermines transaction finality and asset security for decentralized financial operations.

*Deep dive: `TIER_2_CVE-2026-58262.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine