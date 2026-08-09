# **Infrastructure Daily Brief: 2026-08-08**

**Infrastructure Daily Report TLP:GREEN Alert Id: 864d0716 2026-08-09 01:52:16**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.f      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.g      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass           | 1.e      |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.g      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j      |
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | S | 1.f      |
| Threats    | CVE-2026-47662                                                                   | 1.b      |
| Threats    | CVE-2026-47660                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.f**

Source: ketch Published: 2026-08-08

Threat actors are leveraging AI to automate device code phishing at scale, generating live authentication prompts on demand. This campaign bypasses traditional MFA by tricking users into authorizing malicious OAuth consent grants. IT defenders should monitor for anomalous consent requests, enforce conditional access policies, and deploy AI-driven detection to identify automated credential harvesting infrastructure.

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.g**

Source: ketch Published: 2026-08-08

Recent telemetry reveals a surge in device code phishing attacks targeting enterprise identity providers. Attackers exploit the convenience of QR-based and short-code authentication flows to harvest valid tokens without triggering standard MFA alerts. Infrastructure teams must implement strict OAuth scope restrictions, monitor for rapid sequential consent approvals, and educate users on verifying authorization prompts.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://trendmicro.com/en/research/26/g/device-code-phishing.html)**

**PIR: 1.e**

Source: ketch Published: 2026-08-08

This analysis details how device code authentication mechanisms are weaponized to circumvent multi-factor authentication. By redirecting users to spoofed consent pages, adversaries obtain long-lived access tokens that persist even after password resets. Defenders should prioritize token lifecycle management, enforce just-in-time access, and deploy identity threat detection platforms to flag suspicious OAuth grant patterns.

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.g**

Source: ketch Published: 2026-08-08

Device code phishing represents a paradigm shift in identity attacks, rendering traditional MFA controls ineffective. Attackers exploit legitimate authentication endpoints to harvest consent grants, enabling persistent access to cloud environments. IT infrastructure teams must adopt zero-trust identity architectures, restrict device code flows to approved applications, and implement behavioral analytics to detect automated consent harvesting.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j**

Source: ketch Published: 2026-08-08

Identity takeover campaigns are evolving beyond credential stuffing to exploit OAuth device code flows. This report outlines attack chains where adversaries combine social engineering with automated token harvesting to maintain persistent access. Security operations centers should correlate identity logs with network telemetry, enforce strict consent policies, and deploy phishing-resistant MFA alternatives to mitigate token-based compromises.

___________________________________


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.f**

Source: ketch Published: 2026-08-08

This deep dive examines the convergence of illicit consent grants and AI-powered phishing-as-a-service platforms. Attackers now automate the entire device code phishing lifecycle, from victim targeting to token extraction. Infrastructure defenders must audit third-party application permissions, implement continuous consent monitoring, and integrate identity threat intelligence to disrupt AI-driven credential harvesting campaigns.

___________________________________


# **[CVE-2026-47662](https://nvd.nist.gov/vuln/detail/CVE-2026-47662)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-07

Pathling is a set of tools that make it easier to use FHIR and clinical terminology within health data analytics. Prior to version 2.0.0 of Pathling Server, Pathling's typed CRUD/search/batch FHIR surface allows an authenticated caller with only coarse operation authorities to act on attacker-chosen resource families because those entrypoints do not consistently enforce the documented per-resource `read` and `write` authorities. The documented authorization model requires an operation authority 

___________________________________


# **[CVE-2026-47660](https://nvd.nist.gov/vuln/detail/CVE-2026-47660)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-07

Pathling is a set of tools that make it easier to use FHIR and clinical terminology within health data analytics. Prior to version 2.0.0 of Pathling Server, Pathling's bulk-submit operation allows an allowed submitter to supply an explicit `oauthMetadataUrl` parameter that is not validated against `pathling.bulkSubmit.allowableSources`. When present, the bulk-submit OAuth flow trusts metadata and the returned `token_endpoint` from the caller-chosen location, then builds outbound OAuth client aut

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine