# Infrastructure Weekly Capture (IWC): 2026-08-10 - 2026-08-16

## 1. Weekly threat overview

### 1.1 Executive summary

The six-day reporting period captured 153 total items, driven primarily by a significant volume of vulnerability disclosures comprising 105 CVE entries. The week-over-week tone indicates a steady stream of moderate-risk exposures, with the sample data reflecting a concentration of Tier 2 classifications. Crucially, the Global Network active CVE count remains at zero, signaling that the environment is free from critical, actively exploited vulnerabilities. This metric allows the security posture to remain defensive and proactive, focusing on systematic remediation of the disclosed flaws rather than reactive incident response.

Adversary activity is characterized by a sharp escalation in OAuth Device Code Phishing, a sophisticated threat mode that undermines standard authentication controls. Intelligence reports document a 37x surge in enterprise account takeover attempts utilizing this vector, which exploits the device authorization flow to render multi-factor authentication (MFA) ineffective. This attack pattern, frequently linked to illicit consent grants and AI-enhanced Phishing-as-a-Service (PhaaS) campaigns, represents a high-priority risk to identity security. Mitigation efforts must prioritize the review of OAuth consent policies, implementation of strict device code validation, and user education to recognize these MFA-bypassing techniques.

Infrastructure operations are centered on managing the remediation backlog associated with the 105 new CVEs while preserving service availability. The operational focus is on triaging Tier 2 vulnerabilities to ensure timely patching without introducing instability, supported by the absence of GN active CVEs which confirms no immediate critical threats are impacting production systems. Maintenance activities should proceed according to schedule, with additional emphasis on validating identity infrastructure configurations against the emerging OAuth phishing threats. Coordination between patch management and identity teams is essential to address both the software vulnerability surface and the evolving attack vectors simultaneously.

System stability and resilience remain strong, underpinned by the zero GN active CVE count and the lack of service-disrupting events during the capture window. Resilience against the current threat landscape, however, hinges on strengthening identity defenses against the OAuth Device Code Phishing surge. While traditional infrastructure stability is intact, the organization must enhance its resilience posture by hardening authentication flows and deploying detection mechanisms for illicit consent grants. Continuous monitoring of the 153 captured items and rapid adaptation to the 37x increase in phishing attempts will be critical to maintaining robust operational resilience in the coming weeks.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |             85 |
| 1.b   |             22 |
| 1.f   |              8 |
| 1.j.3 |              6 |
| 1.i   |              4 |
| 1.a   |              4 |
| 1.e   |              4 |
| 1.c   |              4 |
| 1.d   |              4 |
| 1.g   |              4 |
| 1.k   |              3 |
| 1.j   |              3 |
| 1.b.2 |              1 |
| 1.b.3 |              1 |

### 1.3 Horizon bullets

- [CVE-2026-72564 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-72564) (2026-08-10)
- [CVE-2026-72575 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-72575) (2026-08-10)
- [CVE-2026-10754 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-10754) (2026-08-10)
- [CVE-2026-10579 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-10579) (2026-08-11)
- [CVE-2026-15556 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-15556) (2026-08-11)
- [CVE-2026-49179 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-49179) (2026-08-11)
- [CVE-2026-11923 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-11923) (2026-08-12)
- [CVE-2026-12359 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-12359) (2026-08-12)
- [CVE-2026-13267 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-13267) (2026-08-12)
- [CVE-2026-17206 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-17206) (2026-08-13)
- [CVE-2026-49478 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-49478) (2026-08-13)
- [CVE-2026-73302 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73302) (2026-08-13)
- [CVE-2026-19764 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19764) (2026-08-14)
- [CVE-2026-19870 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19870) (2026-08-14)
- [OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf) (2026-08-14)
- [Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale](https://www.microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale/) (2026-08-16)
- [Inside Kali365, a Device Code Phishing Ecosystem](https://www.huntress.com/blog/kali365-device-code-phishing-kit) (2026-08-16)
- [The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave](https://slashid.com/blog/illicit-consent-grant-part-2) (2026-08-16)

## 2. DPI Stories of the Week


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.i**

Source: ketch Published: 2026-08-10

This campaign combines AI-generated lures with OAuth device code flows to bypass traditional email filters and MFA. Attackers trick users into entering device codes on malicious portals, granting them direct access to corporate accounts. Defenders should monitor for unusual device code authorization requests, restrict OAuth app permissions, and deploy identity threat detection solutions that flag rapid, automated consent grants across cloud directories.



___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.i**

Source: ketch Published: 2026-08-10

Device code phishing exploits legitimate OAuth flows to harvest valid access tokens, effectively neutralizing password-based MFA. This report outlines the technical mechanics of token theft and lateral movement within cloud environments. IT infrastructure defenders must implement strict OAuth consent policies, monitor for high-privilege token issuance, and deploy identity-aware proxies to validate authentication contexts before granting resource access.



___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.i**

Source: ketch Published: 2026-08-10

Attackers increasingly leverage cloud-native services like serverless functions and object storage to host phishing infrastructure, evading traditional perimeter defenses. This report details how threat actors abuse legitimate cloud APIs to dynamically generate malicious landing pages, rotate domains, and bypass DNS blacklists. Infrastructure defenders must implement cloud workload protection platforms, monitor anomalous API calls, and enforce strict egress filtering to detect and disrupt these 



___________________________________


# **[New widespread EvilTokens kit: device code phishing as-a-service](https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1)**

**PIR: 1.k**

Source: ketch Published: 2026-08-10

The EvilTokens kit has evolved into a full-featured device code phishing-as-a-service platform, enabling low-skill actors to conduct sophisticated identity theft. The infrastructure supports multi-tenant phishing portals and automated token harvesting. Defenders should block known EvilTokens infrastructure, implement zero-trust identity architectures, and enforce just-in-time access controls to limit the blast radius of compromised credentials and stolen OAuth tokens.



___________________________________


# **[Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf)**

**PIR: 1.k**

Source: ketch Published: 2026-08-10

Despite law enforcement takedowns, the Tycoon2FA Phishing-as-a-Service platform has rapidly re-emerged, demonstrating the resilience of modern MaaS ecosystems. The kit facilitates real-time session hijacking and MFA bypass by proxying authentication requests. Infrastructure teams must enforce phishing-resistant MFA standards like FIDO2, monitor for anomalous authentication proxy traffic, and implement conditional access policies that restrict login locations and device compliance to mitigate ses



___________________________________


# **[Inside Kali365, a Device Code Phishing Ecosystem | Huntress](https://www.huntress.com/blog/kali365-device-code-phishing-kit)**

**PIR: 1.k**

Source: ketch Published: 2026-08-10

Kali365 operates as a comprehensive device code phishing ecosystem, offering attackers ready-made infrastructure, victim tracking, and automated credential harvesting. This analysis reveals how the platform scales identity attacks across multiple cloud providers. Infrastructure teams must integrate threat intelligence feeds tracking Kali365 indicators, monitor cloud audit logs for suspicious consent grants, and enforce strict application allow-listing to prevent unauthorized OAuth integrations.



___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.j**

Source: ketch Published: 2026-08-10

Generative AI has transformed phishing from broad, low-success campaigns into highly targeted, autonomous operations. This analysis explores how LLMs craft context-aware lures, automate multi-stage social engineering, and dynamically adapt to victim responses. Defenders should prioritize AI-driven email security gateways, implement continuous user training focused on AI-generated content detection, and deploy behavioral analytics to identify subtle deviations in communication patterns that signa



___________________________________


# **[Storm-2372 conducts device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)**

**PIR: 1.a**

Source: ketch Published: 2026-08-10

The APT group Storm-2372 has adopted device code phishing to target government and defense contractors, leveraging legitimate Microsoft 365 flows to bypass security controls. This campaign highlights the convergence of state-sponsored threat actors and commercial phishing kits. Defenders should monitor for anomalous device code usage patterns, implement advanced identity protection rules, and conduct regular access reviews to detect and revoke compromised service principals and user tokens.



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       6 |
| Total intelligence items |     153 |
| CVE-related items        |     105 |
| GreyNoise-active CVEs    |       0 |

### 4.2 Featured exploitation

See daily `daily_exploitation_pulse.md` files in each edition folder.

### 4.3 Featured CVEs

See daily `daily_critical_cves.md` and WAVE `TIER_*_CVE-*.md` reports.

### 4.4 Campaign / phishing summary

See daily `daily_phishing_campaigns.md` files.

## 5. Infrastructure environment snapshot

### 5.1 Major outages / advisories

_Derived from daily brief items tagged policy or infrastructure_ops._

### 5.2 Supply chain signals

_Review daily Cyber news and Vulners top-50 snapshots under `raw/`._

### 5.3 Policy and standards

_Review daily Policy and standards sections._

## 6. Reporting synopsis

### 6.1 Daily briefs published this week

- `/root/cyber-threat-observatory/reports/2026-08-10/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-11/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-12/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-13/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-14/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-16/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine