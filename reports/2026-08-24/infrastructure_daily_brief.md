# **Infrastructure Daily Brief: 2026-08-24**

**Infrastructure Daily Report TLP:GREEN Alert Id: 803925cb 2026-08-25 04:17:49**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-78246 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-78245 (Tier 2)                                                          | 3.k      |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                          | 1.d      |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.g      |
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | S | 1.c      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.c      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.b      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.d      |
| Threats    | A New Era Of Social Engineering: The Device Code Phishing Boom                   | 1.a      |
| Threats    | Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption            | 1.g      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.d**

Source: ketch Published: 2026-08-24

Enterprise account takeover attacks leveraging OAuth device code flows have surged by 37%, exploiting legitimate authentication mechanisms to bypass traditional MFA. Attackers trick users into entering device codes on malicious portals, granting them direct access to corporate accounts without password theft. This report outlines the technical mechanics of the exploit, detection signatures for anomalous device code grants, and mitigation strategies including conditional access policies and user 

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.g**

Source: ketch Published: 2026-08-24

Traditional MFA implementations are increasingly rendered ineffective by device code phishing, which exploits the trust inherent in OAuth authorization flows. Attackers no longer need to steal passwords or intercept one-time codes; instead, they manipulate users into voluntarily granting access. This article breaks down the attack lifecycle, highlights vulnerabilities in default identity provider configurations, and outlines defensive measures including phishing-resistant MFA adoption, continuou

___________________________________


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.c**

Source: ketch Published: 2026-08-24

The convergence of illicit consent grants and AI-driven PhaaS platforms is accelerating the scale and sophistication of device code phishing. Attackers now use generative AI to craft highly personalized lures and automate infrastructure deployment, reducing campaign setup time to minutes. This analysis explores the technical intersection of OAuth abuse and cloud-native hosting, providing defenders with threat hunting queries, consent audit frameworks, and strategies to detect AI-generated phishi

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.c**

Source: ketch Published: 2026-08-24

Modern phishing campaigns increasingly leverage cloud-native infrastructure to bypass traditional security controls. Attackers abuse serverless functions, containerized environments, and ephemeral hosting to host credential-harvesting pages with high resilience. This report details how threat actors utilize legitimate cloud services to scale phishing operations, evade takedown requests, and maintain persistent access. IT defenders must implement cloud workload protection, monitor for anomalous r

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-08-24

Device code phishing represents a critical evolution in identity takeover tactics, effectively neutralizing traditional multi-factor authentication defenses. By leveraging legitimate OAuth flows, attackers bypass password requirements and MFA prompts, directly compromising user sessions. This report examines the technical progression from credential harvesting to consent-based attacks, providing actionable detection rules for SIEM platforms and recommending architectural changes to identity prov

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.d**

Source: ketch Published: 2026-08-24

Recent threat intelligence reveals a tsunami of device code phishing campaigns targeting enterprise environments across multiple sectors. Attackers are automating the generation of fake verification portals and distributing them via SMS, voice calls, and compromised messaging platforms. This analysis details observed TTPs, infrastructure footprints, and the rapid scaling of these operations. Defenders should prioritize identity-centric monitoring, implement strict OAuth consent governance, and d

___________________________________


# **[A New Era Of Social Engineering: The Device Code Phishing Boom](https://coalitioninc.com/blog/security-labs/a-new-era-of-social-engineering-the-device-code-phishing-boom)**

**PIR: 1.a**

Source: ketch Published: 2026-08-24

The proliferation of device code phishing marks a significant shift in social engineering tactics, moving beyond traditional email lures to target authentication workflows directly. Threat actors craft highly contextual prompts that mimic legitimate SSO and MFA verification steps, significantly increasing success rates. This article explores the psychological triggers exploited, provides real-world campaign examples, and recommends infrastructure-level controls such as blocking unapproved OAuth 

___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.g**

Source: ketch Published: 2026-08-24

Despite coordinated law enforcement actions, the Tycoon2FA PhaaS platform has resurfaced, demonstrating remarkable operational resilience. This analysis examines how the infrastructure-as-a-service model enables rapid redeployment across multiple cloud providers, allowing attackers to continue facilitating MFA bypass and account takeover campaigns. Defenders are advised to monitor for known Tycoon2FA infrastructure patterns, enforce strict OAuth consent policies, and deploy adaptive authenticati

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-78246 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-78246)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-24

Healthcare sector relevance due to direct handling of patient records and prescriptions in a clinic management system.

*Deep dive: `TIER_2_CVE-2026-78246.md`*

___________________________________


# **[CVE-2026-78245 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-78245)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-24

TIER 2 unrestricted file upload in an Online Pharmacy System aligns with the Healthcare sector, posing RCE risks to clinical/pharmacy web portals.

*Deep dive: `TIER_2_CVE-2026-78245.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine