# **Infrastructure Daily Brief: 2026-08-09**

**Infrastructure Daily Report TLP:GREEN Alert Id: 7e55ff07 2026-08-10 01:20:19**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | S | 1.f      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.i      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass           | 1.e      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.h      |
| Threats    | Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption            | 1.g      |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.i      |
| Threats    | Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and | 1.a      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.f**

Source: ketch Published: 2026-08-09

Explores the convergence of AI-generated phishing templates and illicit OAuth consent grants via device codes. Attackers automate credential harvesting at scale, bypassing traditional MFA. Infrastructure defenders must audit third-party application permissions, enforce strict conditional access policies, and deploy identity threat detection platforms to monitor anomalous consent requests and token issuance patterns.

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.i**

Source: ketch Published: 2026-08-09

Analyzes the rapid escalation of device code phishing campaigns targeting enterprise OAuth flows. Victims are tricked into entering short codes on attacker-controlled portals, granting full account access. IT teams should disable unnecessary device code grant types in identity providers, implement token binding, and monitor for rapid, high-privilege consent approvals across cloud directories.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://trendmicro.com/en/research/26/g/device-code-phishing.html)**

**PIR: 1.e**

Source: ketch Published: 2026-08-09

Details how device code authentication flows are weaponized to circumvent multi-factor authentication by leveraging pre-authenticated sessions. Defenders must prioritize identity-centric security controls, enforce step-up authentication for sensitive actions, and restrict device code grants to approved applications only. Network egress filtering and DNS sinkholing remain critical for blocking phishing infrastructure.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j**

Source: ketch Published: 2026-08-09

Examines how device code phishing facilitates complete identity takeover by capturing valid OAuth tokens rather than raw credentials. Infrastructure teams should deploy user and entity behavior analytics to detect token abuse, enforce short-lived access tokens, and implement continuous authentication. Regular revocation of stale consent grants is essential for mitigating lateral movement risks.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.h**

Source: ketch Published: 2026-08-09

Investigates how threat actors leverage serverless functions, object storage, and CDN services to host phishing pages that evade traditional URL filtering. Defenders must implement cloud security posture management, monitor for misconfigured storage buckets, and enforce strict egress controls. Integrating cloud-native telemetry with SIEM platforms enables rapid detection of malicious infrastructure provisioning.

___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.g**

Source: ketch Published: 2026-08-09

Documents the operational resilience of the Tycoon2FA Phishing-as-a-Service platform following law enforcement takedowns. Attackers rapidly migrate infrastructure and reuse templated campaigns. Security operations centers should update threat intelligence feeds with known PhaaS indicators, block associated domains at the proxy level, and educate users on recognizing cloned login portals.

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.i**

Source: ketch Published: 2026-08-09

Breaks down the technical mechanics of device code phishing campaigns that render traditional step-up authentication ineffective. Attackers exploit OAuth 2.0 device authorization flows to capture session tokens. Infrastructure defenders should enforce certificate-based authentication, disable device code grants where possible, and implement real-time alerting for unusual consent grant patterns across identity providers.

___________________________________


# **[Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a)**

**PIR: 1.a**

Source: ketch Published: 2026-08-09

CISA advisory detailing targeted spearphishing operations using malicious documents and credential harvesting sites. Defenders must deploy advanced email security gateways with attachment sandboxing, enforce strict URL rewriting, and implement user awareness training. Monitoring for anomalous outbound connections to newly registered domains helps identify early-stage compromise attempts.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine