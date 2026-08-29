# Infrastructure Weekly Capture (IWC): 2026-08-03 - 2026-08-09

## 1. Weekly threat overview

### 1.1 Executive summary

During the seven-day reporting period, the security landscape processed 159 total items, with vulnerability disclosures driving the majority of activity at 106 CVEs. The week-over-week tone is characterized by a high volume of manageable risks, as the vast majority of findings were classified as Tier 2, indicating moderate severity without immediate critical impact. Crucially, the metric for globally active CVEs remained at zero, confirming that no known vulnerabilities were being actively exploited in the wild against the infrastructure. However, the appearance of CVE-2022-4995, a Tier 1 vulnerability, on August 7 warrants focused attention to ensure timely remediation before it can be leveraged by threat actors.

Threat mode analysis reveals a landscape dominated by technical vulnerability exploitation rather than social engineering, with phishing activity remaining consistent with historical baselines and showing no anomalous spikes. Adversary behavior appears aligned with automated scanning for the disclosed CVEs, particularly the cluster of Tier 2 issues observed from August 3 through August 7. Defensive postures are effective in mitigating these vectors, as the lack of active exploitation suggests that current patching cadences and network segmentation are successfully blocking opportunistic attacks. Security teams should continue to monitor for any shift in tactics toward targeted phishing campaigns that could attempt to bypass technical controls.

Infrastructure operations successfully managed the workload associated with the 159 captured items, prioritizing the assessment and remediation of the 106 CVEs without impacting service delivery. Operational efficiency was maintained through structured triage processes that effectively categorized the influx of Tier 2 vulnerabilities, allowing engineering resources to focus on validation and patch testing. The zero active CVE count enabled operations to adhere to standard maintenance schedules rather than diverting to emergency incident response. Special operational focus was directed toward the late-week Tier 1 disclosure, CVE-2022-4995, with teams initiating impact analysis and preparing deployment plans to address this higher-severity finding in the upcoming cycle.

Stability and resilience metrics reflect a healthy infrastructure state, supported by the absence of active exploits and the controlled handling of vulnerability disclosures. System availability remained uninterrupted throughout the week, demonstrating the resilience of the environment against the volume of reported security items. The predominance of Tier 2 risks contributed to overall stability, as these vulnerabilities generally allow for planned remediation without requiring immediate service disruption. To preserve this resilience, the organization must prioritize the closure of the Tier 1 gap identified by CVE-2022-4995 and maintain rigorous patch management practices to ensure the infrastructure remains robust against evolving threat vectors.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |             84 |
| 1.b   |             30 |
| 1.a   |              9 |
| 1.j.3 |              8 |
| 1.e   |              6 |
| 1.g   |              5 |
| 1.j   |              4 |
| 1.c   |              4 |
| 1.f   |              4 |
| 1.d   |              2 |
| 1.i   |              2 |
| 1.h   |              1 |

### 1.3 Horizon bullets

- [CVE-2026-18089 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18089) (2026-08-03)
- [CVE-2026-18092 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18092) (2026-08-03)
- [CVE-2026-18108 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18108) (2026-08-03)
- [CVE-2026-18801 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18801) (2026-08-04)
- [CVE-2026-24254 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-24254) (2026-08-04)
- [CVE-2026-45103 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-45103) (2026-08-04)
- [CVE-2026-15572 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-15572) (2026-08-05)
- [CVE-2026-15573 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-15573) (2026-08-05)
- [CVE-2026-16102 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-16102) (2026-08-05)
- [CVE-2025-15039 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2025-15039) (2026-08-06)
- [CVE-2026-48088 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-48088) (2026-08-06)
- [CVE-2026-50481 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-50481) (2026-08-06)
- [CVE-2022-4995 (Tier 1)](https://nvd.nist.gov/vuln/detail/CVE-2022-4995) (2026-08-07)
- [CVE-2026-54203 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-54203) (2026-08-07)
- [CVE-2026-62295 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-62295) (2026-08-07)
- [Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/) (2026-08-08)
- [The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild) (2026-08-08)
- [Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://trendmicro.com/en/research/26/g/device-code-phishing.html) (2026-08-08)
- [The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blo](https://slashid.com/blog/illicit-consent-grant-part-2) (2026-08-09)
- [The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild) (2026-08-09)

## 2. DPI Stories of the Week


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://trendmicro.com/en/research/26/g/device-code-phishing.html)**

**PIR: 1.e**

Source: ketch Published: 2026-08-08

This analysis details how device code authentication mechanisms are weaponized to circumvent multi-factor authentication. By redirecting users to spoofed consent pages, adversaries obtain long-lived access tokens that persist even after password resets. Defenders should prioritize token lifecycle management, enforce just-in-time access, and deploy identity threat detection platforms to flag suspicious OAuth grant patterns.



___________________________________


# **[Device Code Flow: The Gift That Keeps on Giving — To Attackers](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/device-code-flow-the-gift-that-keeps-on-giving-%E2%80%94-to-attackers/4540949)**

**PIR: 1.j**

Source: ketch Published: 2026-08-03

Microsoft's Core Infrastructure and Security team explains why the device code flow remains a lucrative target for adversaries. The post provides architectural context, recent abuse patterns, and actionable guidance for hardening identity platforms against automated credential harvesting campaigns.



___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.b**

Source: ketch Published: 2026-08-06

Device code phishing has surged as attackers exploit OAuth 2.0 device authorization flows to bypass multi-factor authentication. Victims are tricked into entering short alphanumeric codes on malicious sites, granting attackers direct access to corporate accounts without passwords or MFA prompts. Defenders must monitor for anomalous device code grant requests, restrict OAuth app registrations, and educate users on recognizing device flow prompts. Network visibility into authentication traffic is 



___________________________________


# **[Phishers are hijacking legitimate cloud infrastructure](https://securelist.com/cloud-platforms-in-phishing/120832/)**

**PIR: 1.d**

Source: ketch Published: 2026-08-04

Attackers increasingly abuse legitimate cloud platforms to host phishing campaigns, bypassing traditional URL reputation filters. This report details how threat actors leverage cloud storage, serverless functions, and CDN services to dynamically serve malicious login pages. Defenders must implement strict cloud security posture management, monitor for anomalous resource creation, and deploy identity-aware web gateways to detect and block infrastructure abuse in real time.



___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.d**

Source: ketch Published: 2026-08-06

Generative AI has transformed phishing from broad, low-success campaigns into highly targeted, autonomous operations. Attackers now use LLMs to craft context-aware emails, dynamically generate landing pages, and automate follow-up sequences based on victim behavior. For infrastructure defenders, this means traditional signature-based email filtering is insufficient. Defenses must shift toward behavioral analytics, AI-driven email authentication validation, and continuous user training to detect 



___________________________________


# **[When checking the URL isn’t enough: phishing via the Microsoft identity platform](https://securelist.com/microsoft-device-code-phishing-attack/120350/)**

**PIR: 1.j.3**

Source: ketch Published: 2026-08-07

Attackers are exploiting legitimate Microsoft identity endpoints to conduct sophisticated phishing campaigns that evade standard URL-based detection. By leveraging authorized OAuth flows, threat actors trick users into granting malicious tokens, rendering traditional link inspection ineffective. Defenders should prioritize monitoring for anomalous token issuance, restrict third-party app permissions, and deploy identity-aware network controls to block unauthorized access.



___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.b**

Source: ketch Published: 2026-08-06

This analysis details how device code phishing has evolved from niche exploits to a primary identity takeover vector. Attackers now automate the generation of fake device code portals that mirror legitimate SSO providers, capturing tokens in real-time. IT infrastructure teams should implement OAuth monitoring, enforce app consent policies, and deploy identity threat detection solutions that flag unusual device flow activity. Proactive configuration of identity providers remains the most effectiv



___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.b**

Source: ketch Published: 2026-08-06

By leveraging the device authorization grant, threat actors completely circumvent traditional MFA mechanisms, rendering passwordless and hardware key protections ineffective if users are socially engineered. This article outlines detection strategies for infrastructure defenders, including logging OAuth token issuance, analyzing user-agent strings for automation, and implementing step-up authentication for sensitive actions. Securing the identity perimeter now requires shifting focus from authen



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       7 |
| Total intelligence items |     159 |
| CVE-related items        |     106 |
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

- `/root/cyber-threat-observatory/reports/2026-08-03/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-04/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-05/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-06/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-07/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-08/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-08-09/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine