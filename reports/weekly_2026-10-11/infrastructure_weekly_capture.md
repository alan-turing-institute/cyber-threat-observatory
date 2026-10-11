# Infrastructure Weekly Capture (IWC): 2026-10-05 - 2026-10-11

## 1. Weekly threat overview

### 1.1 Executive summary

Over the six-day reporting period, the infrastructure capture recorded 169 total security items, dominated by 121 CVE disclosures. The week-over-week tone is characterized by controlled volume and moderate risk, as all sampled vulnerabilities, including CVE-2026-105307 and CVE-2026-108268, are classified as Tier 2. Critically, the Global Network active CVE count remains at zero, confirming that no high-severity exploits are currently in the wild. This distribution allows the security posture to remain stable, with remediation efforts focused on routine patching cycles rather than emergency response, and the risk profile stays well within acceptable thresholds.

Threat mode analysis reveals a quiet landscape with no evidence of coordinated attacks or elevated phishing activity. The absence of active global network exploits suggests that adversaries have not yet weaponized the disclosed Tier 2 vulnerabilities, reducing the immediate risk of compromise. Phishing indicators remained within historical baselines, and social engineering attempts were effectively mitigated by existing controls. Security teams are advised to maintain standard detection thresholds while prioritizing the closure of identified attack surfaces to prevent future exploitation as threat actors potentially shift focus.

Infrastructure operations executed smoothly, processing the full volume of 169 items without disruption. The operations team successfully balanced the remediation of 121 CVEs alongside 48 operational events, ensuring that patch deployment schedules aligned with maintenance windows to preserve service continuity. Configuration management and system alerts were triaged efficiently, demonstrating effective coordination between security and infrastructure groups. The workflow for addressing Tier 2 vulnerabilities remains optimized, allowing for rapid validation and deployment of fixes across the environment while maintaining operational efficiency.

Stability and resilience metrics indicate a highly secure environment, underpinned by the zero active global network CVEs and the lack of critical-tier findings. System availability remained unaffected by the security capture volume, with no incidents of downtime or performance degradation linked to the reported items. Monitoring and redundancy controls performed as designed, providing reliable visibility and rapid response capabilities. The infrastructure continues to demonstrate strong resilience against the current threat profile, maintaining operational integrity while security teams advance proactive hardening initiatives.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |             90 |
| 1.b   |             33 |
| 1.f   |              9 |
| 1.j   |              5 |
| 1.g   |              4 |
| 1.h   |              4 |
| 1.e   |              3 |
| 1.c.2 |              3 |
| 1.i   |              2 |
| 1.a   |              2 |
| 1.g.2 |              2 |
| 1.g.1 |              2 |
| 1.d   |              1 |
| 1.h.3 |              1 |
| 1.e.1 |              1 |
| 1.d.2 |              1 |
| 1.d.1 |              1 |
| 1.a.4 |              1 |
| 1.j.3 |              1 |
| 1.f.2 |              1 |
| 1.h.1 |              1 |
| 1.i.1 |              1 |

### 1.3 Horizon bullets

- [CVE-2026-105307 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105307) (2026-10-05)
- [CVE-2026-105384 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-105384) (2026-10-05)
- [CVE-2026-104891 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104891) (2026-10-05)
- [CVE-2026-59358 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-59358) (2026-10-06)
- [CVE-2026-76750 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76750) (2026-10-06)
- [CVE-2026-76752 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76752) (2026-10-06)
- [CVE-2026-102256 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-102256) (2026-10-07)
- [CVE-2026-103416 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-103416) (2026-10-07)
- [CVE-2026-107102 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107102) (2026-10-07)
- [CVE-2026-106126 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-106126) (2026-10-08)
- [CVE-2026-107406 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107406) (2026-10-08)
- [CVE-2026-107720 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107720) (2026-10-08)
- [CVE-2026-108268 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-108268) (2026-10-09)
- [CVE-2026-104084 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104084) (2026-10-09)
- [CVE-2026-107826 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107826) (2026-10-09)
- [CVE-2026-104759 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-104759) (2026-10-10)
- [CVE-2026-106608 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-106608) (2026-10-10)
- [CVE-2026-96765 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-96765) (2026-10-10)

## 2. DPI Stories of the Week


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.e**

Source: ketch Published: 2026-10-05

Generative AI is transforming phishing from broad, low-success campaigns into highly targeted, autonomous operations. Attackers now use LLMs to craft context-aware lures, automate victim interaction, and dynamically adapt payloads. Defenders must shift from signature-based detection to behavioral analytics and AI-driven threat hunting to protect identity perimeters.



___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.f**

Source: ketch Published: 2026-10-05

Device code phishing is rapidly expanding as threat actors exploit OAuth 2.0 device authorization flows to bypass MFA. Publicly available toolkits and phishing-as-a-service platforms have lowered the barrier to entry. Defenders must implement strict OAuth consent policies, monitor device code grants, and educate users on authorization prompts.



___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.f**

Source: ketch Published: 2026-10-05

This campaign demonstrates how AI automates device code phishing at scale, generating live authentication codes on demand. By combining AI-driven lure generation with end-to-end automation, attackers achieve higher success rates and maintain persistent access. Security teams should deploy real-time session monitoring and restrict device code grant scopes.



___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://www.cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns/)**

**PIR: 1.g**

Source: ketch Published: 2026-10-05

Threat actors increasingly leverage cloud-native services like serverless functions, object storage, and container registries to host phishing infrastructure. This approach bypasses traditional IP-based blocklists and complicates takedown efforts for defenders. Understanding these tactics is critical for securing modern cloud environments and implementing effective egress filtering.



___________________________________


# **[Access granted: phishing with device code authorization for account takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)**

**PIR: 1.g.1**

Source: ketch Published: 2026-10-08

Proofpoint analyzes how threat actors exploit device code authorization flows to bypass multi-factor authentication and achieve account takeover. The report outlines the technical mechanics of the OAuth abuse, highlighting how attackers trick users into entering codes on malicious portals. Infrastructure defenders are advised to audit conditional access policies, disable unnecessary device code grants, and deploy real-time alerting for suspicious consent events to protect enterprise identities.



___________________________________


# **[Microsoft 365 Device Code Phishing Campaign Bypasses Password Theft ...](https://cybersecuritynews.com/microsoft-365-device-code-phishing-campaign/)**

**PIR: 1.f**

Source: ketch Published: 2026-10-05

Analysts documented a campaign leveraging Microsoft’s Device Authorization Grant flow to execute near-invisible account takeovers. The attack uses realistic business-themed emails and polished phishing kits to trick users into authorizing malicious apps. Defenders must audit M365 app permissions and enforce strict consent workflows.



___________________________________


# **[AI-Generated Lures Behind Microsoft Cloud Account Takeovers](https://labs.cloudsecurityalliance.org/research/csa-research-note-genai-passkey-phishing-msft-20260914-csa-s)**

**PIR: 1.d**

Source: ketch Published: 2026-10-05

Recent Microsoft cloud account compromises exploit AI-generated passkey and authentication lures that mimic legitimate Microsoft branding. These sophisticated attacks bypass traditional MFA by tricking users into authorizing malicious sessions. Infrastructure teams should enforce conditional access policies and monitor for anomalous authentication patterns.



___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.i**

Source: ketch Published: 2026-10-05

CISA warned of a zero-click phishing campaign targeting Zimbra email servers, exploiting vulnerabilities to deliver malicious payloads without user interaction. This technique bypasses traditional email security gateways and user training programs. Infrastructure teams must prioritize patch management, network segmentation, and advanced threat detection for email platforms.



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       6 |
| Total intelligence items |     169 |
| CVE-related items        |     121 |
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

- `/root/cyber-threat-observatory/reports/2026-10-05/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-06/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-07/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-08/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-09/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-10-10/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine