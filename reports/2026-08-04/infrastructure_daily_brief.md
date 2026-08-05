# **Infrastructure Daily Brief: 2026-08-04**

**Infrastructure Daily Report TLP:GREEN Alert Id: cae46c8a 2026-08-05 16:49:42**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-18801 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-24254 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-45103 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-45537 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-56848 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-58073 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-67195 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-67200 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-70482 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-10050 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-58067 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-63456 (Tier 2)                                                          | 3.k      |
| Threats    | Phishers are hijacking legitimate cloud infrastructure                           | 1.d      |
| Threats    | When checking the URL isn’t enough: phishing via the Microsoft identity platform | 1.b      |
| Threats    | Inside Kali365, a Device Code Phishing Ecosystem | Huntress                      | 1.c      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend M | 1.b      |
| Threats    | IronToll: Global Government-Impersonation PhaaS | PhishEye                       | 1.c      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.e      |
| Threats    | Talos: Attackers Refine Phishing Playbook To Target Critical Infrastructure      | 1.g      |
| Threats    | Operation HookedWing: Four-Year Phishing Campaign Hits 500 ...                   | 1.g      |
| Threats    | CVE-2026-18108                                                                   | 1.b      |
| Threats    | CVE-2026-67610                                                                   | 1.b      |
| Threats    | CVE-2026-18092                                                                   | 1.b      |
| Threats    | CVE-2026-18089                                                                   | 1.b      |
| Threats    | CVE-2026-18651                                                                   | 1.b      |
| Threats    | CVE-2026-18569                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Phishers are hijacking legitimate cloud infrastructure](https://securelist.com/cloud-platforms-in-phishing/120832/)**

**PIR: 1.d**

Source: ketch Published: 2026-08-04

Attackers increasingly abuse legitimate cloud platforms to host phishing campaigns, bypassing traditional URL reputation filters. This report details how threat actors leverage cloud storage, serverless functions, and CDN services to dynamically serve malicious login pages. Defenders must implement strict cloud security posture management, monitor for anomalous resource creation, and deploy identity-aware web gateways to detect and block infrastructure abuse in real time.

___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform | Securelist](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.b**

Source: ketch Published: 2026-08-04

Modern phishing campaigns exploit the Microsoft identity platform by leveraging legitimate OAuth endpoints and device code flows to bypass traditional URL-based defenses. Attackers craft convincing prompts that redirect users to authentic Microsoft domains, making visual inspection ineffective. Infrastructure defenders should enforce conditional access policies, monitor for suspicious device code requests, and deploy identity protection tools that analyze authentication context rather than relyi

___________________________________


# **[Inside Kali365, a Device Code Phishing Ecosystem | Huntress](https://www.huntress.com/blog/kali365-device-code-phishing-kit)**

**PIR: 1.c**

Source: ketch Published: 2026-08-04

Kali365 operates as a sophisticated Phishing-as-a-Service (PhaaS) platform specializing in device code attacks. The ecosystem provides affiliates with customizable landing pages, automated token harvesting, and real-time credential forwarding. Defenders must monitor for anomalous OAuth device code requests, implement step-up authentication for sensitive actions, and integrate threat intelligence feeds to block known Kali365 infrastructure and associated redirect domains.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass | Trend Micro (US)](https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.b**

Source: ketch Published: 2026-08-04

Device code authentication, designed for screenless devices, is increasingly weaponized to bypass multi-factor authentication. Attackers trick users into entering codes on malicious sites, granting them direct access to accounts without triggering traditional MFA prompts. IT infrastructure teams should restrict device code flows to approved applications, enforce risk-based authentication, and deploy user education campaigns highlighting the dangers of entering verification codes on untrusted pla

___________________________________


# **[IronToll: Global Government-Impersonation PhaaS | PhishEye](https://phisheye.com/blog/irontoll-iron-man-phaas-campaign)**

**PIR: 1.c**

Source: ketch Published: 2026-08-04

IronToll is a large-scale PhaaS operation targeting government and enterprise sectors through highly customized impersonation campaigns. The platform offers affiliates modular phishing kits, automated domain generation, and credential harvesting dashboards. Defenders should monitor for newly registered domains mimicking government agencies, implement email authentication standards (DMARC/DKIM/SPF), and deploy AI-driven phishing detection to identify template variations and dynamic content inject

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.e**

Source: ketch Published: 2026-08-04

Threat actors are integrating generative AI to automate and personalize device code phishing attacks at scale. AI models dynamically generate context-aware prompts, adapt language based on user interaction, and optimize landing pages for higher conversion rates. Infrastructure defenders must deploy behavioral analytics to detect AI-generated content patterns, enforce strict OAuth scope limitations, and implement continuous authentication monitoring to identify anomalous device code usage across 

___________________________________


# **[Talos: Attackers Refine Phishing Playbook To Target Critical Infrastructure](https://securityledger.com/2026/07/talos-attackers-refine-phishing-playbook-to-target-critical-infrastructure/)**

**PIR: 1.g**

Source: ketch Published: 2026-08-04

Cybercriminals are adapting phishing tactics to specifically target healthcare, local government, and critical infrastructure sectors. Campaigns leverage trusted technology abuse, supply chain impersonation, and sector-specific lures to evade detection. Defenders should implement zero-trust network architectures, enforce strict email filtering with AI-based content analysis, and conduct regular phishing simulations tailored to critical infrastructure workflows to strengthen human and technical d

___________________________________


# **[Operation HookedWing: Four-Year Phishing Campaign Hits 500 ...](https://cybersecurityjournal.ca/techtalk/84066-operation-hookedwing-phishing-aviation-critical-infrastructure-2026-05-11/)**

**PIR: 1.g**

Source: ketch Published: 2026-08-04

Operation HookedWing represents a persistent, long-running credential harvesting campaign targeting aviation, critical infrastructure, and government entities. Attackers utilize rotating domains, legitimate cloud hosting, and social engineering tailored to sector-specific compliance requirements. Infrastructure defenders must maintain continuous threat hunting for known HookedWing indicators, enforce multi-factor authentication with phishing-resistant methods, and monitor for lateral movement fo

___________________________________


# **[CVE-2026-18108](https://nvd.nist.gov/vuln/detail/CVE-2026-18108)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-03

Net::SAML2 versions before 0.86 for Perl allow authentication bypass because _verify_encrypted_assertion accepts an EncryptedAssertion whose decrypted content carries no signature.

_verify_encrypted_assertion decrypts the EncryptedAssertion and returns it as verified when it carries no signature, via "return $xml unless $xpath->exists('dsig:Signature', $assert);". The signature check and the trust anchor check that follow run only when a signature is present, so a decrypted assertion with no ds

___________________________________


# **[CVE-2026-67610](https://nvd.nist.gov/vuln/detail/CVE-2026-67610)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-03

OpenEMR through 8.2.0 contains an improper authentication vulnerability in the OAuth2 dynamic client registration endpoint that allows unauthenticated attackers to register a malicious client with system-level FHIR scopes by supplying a self-generated RSA keypair via the jwks field. Once an administrator approves the registered client, attackers can use the client_credentials grant with a self-signed JWT assertion to obtain access tokens granting read access to all FHIR resources across all pati

___________________________________


# **[CVE-2026-18092](https://nvd.nist.gov/vuln/detail/CVE-2026-18092)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-03

Net::SAML2 versions before 0.86 for Perl allow SAML authentication bypass via XML signature wrapping because new_from_xml reads assertion identity with document-wide XPath instead of the signed subtree.

new_from_xml reads the NameID, attribute values, SessionIndex, audience and other identity fields with document-wide XPath, such as //saml:Assertion/saml:AttributeStatement/saml:Attribute and //saml:Subject/saml:NameID, which select the first matching element in document order rather than the el

___________________________________


# **[CVE-2026-18089](https://nvd.nist.gov/vuln/detail/CVE-2026-18089)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-03

Net::SAML2 versions before 0.86 for Perl allow SAML authentication bypass by verifying responses against the response-embedded certificate in verify_xml when no trust anchor is configured.

verify_xml in Net::SAML2::Role::VerifyXML runs "return if !$anchors && !$cacert;" as soon as the XML::Sig check succeeds, and that check uses the X.509 certificate taken from the response's own dsig:KeyInfo/dsig:X509Certificate element, so an unanchored response is checked only against the key it carries. Bin

___________________________________


# **[CVE-2026-18651](https://nvd.nist.gov/vuln/detail/CVE-2026-18651)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-03

A flaw was found in 389 Directory Server. During SASL PLAIN authentication, the server installs connection-level bind credentials before performing the account-lock check. If the account is subsequently found to be locked, the bind is reported as failed to the client, but the already-installed authenticated state on the connection is not reverted. A client that supplies valid credentials for an account that has been administratively locked can continue to use the same connection with that accoun

___________________________________


# **[CVE-2026-18569](https://nvd.nist.gov/vuln/detail/CVE-2026-18569)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-04

A flaw was found in the backchannel logout endpoint of the keycloak-services component, which is part of the Red Hat Build of Keycloak. This component handles authentication and session management for applications. The issue occurs when an OIDC identity provider is configured to skip signature validation. In this specific setup, the system incorrectly accepts logout requests that have no cryptographic signature. An attacker who knows certain technical details about a user's session can use this 

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-18801 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18801)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Finance sector: Critical cross-tenant SQLi in a SaaS billing and metering backend threatens payment data integrity and revenue operations.

*Deep dive: `TIER_2_CVE-2026-18801.md`*

___________________________________


# **[CVE-2026-24254 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-24254)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

TIER 2 unauthenticated RCE in NVIDIA Dynamo AI orchestration, a foundational general infrastructure component supporting compute-intensive workloads across critical public and regulated sectors.

*Deep dive: `TIER_2_CVE-2026-24254.md`*

___________________________________


# **[CVE-2026-45103 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-45103)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Foundational telecom/VoIP infrastructure underpinning Finance, Healthcare, and Government communications, with unauthenticated SIP smuggling bypassing security policies.

*Deep dive: `TIER_2_CVE-2026-45103.md`*

___________________________________


# **[CVE-2026-45537 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-45537)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Critical telecom signaling infrastructure vulnerability impacting national VoIP resilience and public communications continuity.

*Deep dive: `TIER_2_CVE-2026-45537.md`*

___________________________________


# **[CVE-2026-56848 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-56848)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

General infrastructure flaw in Node.js HTTP/2 handling impacting public-facing APIs and web servers foundational to Digital Identity, Finance, Healthcare, and Government services.

*Deep dive: `TIER_2_CVE-2026-56848.md`*

___________________________________


# **[CVE-2026-58073 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-58073)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Critical backup infrastructure widely deployed across Government, Healthcare, and Finance sectors; unauthenticated bypass on internet-exposed gateways threatens multi-tenant data resilience and business continuity.

*Deep dive: `TIER_2_CVE-2026-58073.md`*

___________________________________


# **[CVE-2026-67195 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67195)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Finance sector: unauthenticated RCE in internal analytics dashboards widely deployed in banking and trading environments, enabling lateral movement and data compromise.

*Deep dive: `TIER_2_CVE-2026-67195.md`*

___________________________________


# **[CVE-2026-67200 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67200)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Unauthenticated path traversal in a FINOS-backed analytics dashboard widely deployed in banking and trading environments, risking credential and market data exfiltration.

*Deep dive: `TIER_2_CVE-2026-67200.md`*

___________________________________


# **[CVE-2026-70482 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-70482)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Direct OAuth token exchange bypass enabling full account takeover, impacting Digital Identity and session management in self-hosted enterprise/AI deployments.

*Deep dive: `TIER_2_CVE-2026-70482.md`*

___________________________________


# **[CVE-2026-10050 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-10050)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Foundational Java web server authentication bypass impacting API gateways and backend services commonly deployed in regulated/public digital infrastructure.

*Deep dive: `TIER_2_CVE-2026-10050.md`*

___________________________________


# **[CVE-2026-58067 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-58067)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Unauthenticated DoS in internet-facing backup management console disrupts disaster recovery operations across Finance, Healthcare, and Government deployments.

*Deep dive: `TIER_2_CVE-2026-58067.md`*

___________________________________


# **[CVE-2026-63456 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-63456)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-04

Critical unauthenticated REST API bypass in HPE SD-WAN Orchestrator, a foundational networking component explicitly deployed in government and enterprise environments.

*Deep dive: `TIER_2_CVE-2026-63456.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine