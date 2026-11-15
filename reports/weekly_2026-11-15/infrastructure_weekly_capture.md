# Infrastructure Weekly Capture (IWC): 2026-11-09 - 2026-11-15

## 1. Weekly threat overview

### 1.1 Executive summary

Over the six-day reporting period, infrastructure intelligence captured 239 total items, with vulnerability management dominating the landscape as 191 entries (approximately 80%) were classified as CVEs. This volume indicates a sustained high rate of vulnerability disclosures, averaging roughly 32 CVEs per day. Despite the intense CVE churn, the week-over-week tone remains controlled; the metric for GN active CVEs stands at zero, signaling that no critical, actively exploited vulnerabilities have impacted the global network. This absence of active critical threats suggests that while the attack surface is expanding rapidly, immediate risk to core operations is contained, allowing teams to focus on systematic remediation and patching cycles rather than emergency crisis response.

Threat analysis reveals a pronounced focus on identity compromise and advanced social engineering, with phishing emerging as the primary threat mode. Intelligence highlights a significant evolution in device code phishing, which adversaries are exploiting as a sophisticated mechanism for identity takeover, often circumventing standard authentication defenses. Compounding this risk, reports detail AI-enabled device code phishing campaigns that leverage automation to increase the scale and precision of attacks. Additionally, joint advisories emphasize state-sponsored spear-phishing campaigns specifically targeting critical infrastructure, indicating a coordinated effort by advanced threat actors to exploit human and process vulnerabilities within essential services.

Infrastructure operations are prioritizing the mitigation of the high CVE volume and hardening defenses against the identified phishing vectors. Operational efforts are concentrated on triaging and patching the influx of Tier 2 vulnerabilities to prevent accumulation of technical debt and reduce exploitable surface area. Concurrently, engineering and security teams are reviewing identity infrastructure configurations to detect and block device code phishing attempts, ensuring that authentication protocols are resilient against the observed AI-driven tactics. Cross-functional coordination is essential to align patching schedules with threat intelligence, ensuring that remediation efforts are optimized based on the active targeting of critical infrastructure by state-sponsored groups.

System stability and resilience are currently maintained, underpinned by the zero count of GN active CVEs and the lack of reported service disruptions. The infrastructure demonstrates robustness against the current threat wave, as no critical vulnerabilities have transitioned to active exploitation status. However, long-term resilience depends on the organization's ability to manage the operational load imposed by the high CVE volume and the evolving sophistication of phishing attacks. Sustaining this stability requires continued discipline in vulnerability lifecycle management, enhanced monitoring for anomalous identity behavior, and proactive adaptation of security controls to counter the AI-enabled and state-sponsored threats characterizing the current threat environment.

### 1.2 PIR breakdown

| PIR   |   Report Total |
|-------|----------------|
| 3.k   |            152 |
| 1.b   |             47 |
| 1.a   |              9 |
| 1.c   |              6 |
| 1.d   |              5 |
| 1.f   |              5 |
| 1.g   |              3 |
| 1.b.2 |              3 |
| 1.e   |              2 |
| 1.b.1 |              2 |
| 1.h   |              1 |
| 1.i   |              1 |
| 1.j.3 |              1 |
| 1.c.1 |              1 |
| 1.d.1 |              1 |

### 1.3 Horizon bullets

- [CVE-2026-124554 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124554) (2026-11-09)
- [The Infrastructure Behind Phishing | Zerot Security Research](https://research.zerot-security.com/the-infrastructure-behind-phishing/) (2026-11-09)
- [Device Code Phishing is an Evolution in Identity Takeover](https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover) (2026-11-09)
- [CVE-2026-109799 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-109799) (2026-11-10)
- [CVE-2026-112966 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-112966) (2026-11-10)
- [CVE-2026-119958 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119958) (2026-11-10)
- [CVE-2026-126238 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126238) (2026-11-11)
- [CVE-2026-126240 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126240) (2026-11-11)
- [CVE-2026-126245 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126245) (2026-11-11)
- [CVE-2026-111552 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111552) (2026-11-12)
- [CVE-2026-116335 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116335) (2026-11-12)
- [CVE-2026-120868 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120868) (2026-11-12)
- [CVE-2026-107412 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107412) (2026-11-13)
- [CVE-2026-107413 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-107413) (2026-11-13)
- [CVE-2026-126451 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-126451) (2026-11-13)
- [CVE-2026-129456 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129456) (2026-11-14)
- [Device Code Phishing is an Evolution in Identity Takeover](https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover) (2026-11-14)
- [Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026) (2026-11-14)

## 2. DPI Stories of the Week


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing)**

**PIR: 1.j.3**

Source: ketch Published: 2026-11-10

EvilTokens represent a critical evolution in identity compromise, where attackers steal long-lived OAuth refresh tokens via device code phishing. These tokens grant persistent, passwordless access to cloud environments, often evading traditional SIEM alerts. Defenders should enforce short token lifespans, implement continuous access evaluation, and deploy identity-specific EDR solutions to detect and revoke malicious token usage across hybrid infrastructure.



___________________________________


# **[Device code phishing bypasses password stealing](https://reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.f**

Source: ketch Published: 2026-11-10

Traditional password phishing is increasingly obsolete as attackers pivot to device code flows that directly harvest OAuth tokens. This technique circumvents password-based MFA and conditional access policies tied to credential validation. Security operations must shift focus to token lifecycle management, implement strict OAuth consent policies, and deploy identity threat detection platforms capable of correlating device code usage with anomalous authentication patterns.



___________________________________


# **[Multi-Hop Google Redirects Phishing Campaign Analysis 2026](https://aviatrix.ai/threat-research-center/multi-hop-google-redirects-phishing-campaign-2026/)**

**PIR: 1.b**

Source: ketch Published: 2026-11-10

Threat actors chain Google Meet, DoubleClick, and Custom Search to create multi-hop redirect sequences that bypass security gateways. This campaign dynamically constructs legitimate-looking URLs to evade URL filtering and proxy inspection. Defenders should monitor for unusual Google service chaining, implement strict egress filtering, and deploy AI-driven URL reputation checks to detect these evasion tactics before credential harvesting occurs.



___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.b**

Source: ketch Published: 2026-11-13

Details a campaign exploiting the device code flow to bypass password-based MFA and credential theft defenses. Attackers trick users into authorizing malicious apps, granting full tenant access. IT teams should restrict device code grant types in Azure AD, enforce risk-based conditional access, and monitor for high-privilege token issuance from unfamiliar IP ranges to prevent identity compromise.



___________________________________


# **[Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing](https://huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing)**

**PIR: 1.f**

Source: ketch Published: 2026-11-10

Attackers abuse Microsoft Teams meeting booking workflows to deliver device code phishing prompts disguised as legitimate calendar invitations. By embedding malicious OAuth authorization requests within trusted Teams UI elements, threat actors bypass user suspicion and security controls. IT teams should audit Teams app permissions, restrict external meeting bookings, and deploy endpoint detection rules to flag unauthorized OAuth consent requests originating from collaboration platforms.



___________________________________


# **[Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/)**

**PIR: 1.c**

Source: ketch Published: 2026-11-10

The Midnight Blizzard threat group distributes spear-phishing emails containing malicious RDP files designed to bypass email security filters and establish remote access. These files often leverage signed binaries and living-off-the-land techniques to evade endpoint detection. Defenders should block RDP file execution via application control, monitor for unusual PsExec or WMI activity, and enforce strict remote access policies to mitigate this persistent threat.



___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime](https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime)**

**PIR: 1.a**

Source: ketch Published: 2026-11-11

Analyzes the underground infrastructure powering modern phishing operations, detailing proxy networks, domain generation algorithms, and hosting providers. Provides actionable indicators for blocking upstream infrastructure and disrupting attacker supply chains before campaigns scale.



___________________________________


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.a**

Source: ketch Published: 2026-11-12

Analyzes the underground infrastructure supporting large-scale phishing operations, detailing domain generation algorithms, bulletproof hosting networks, and CDN abuse tactics. Provides actionable IOCs and architectural insights for network defenders to block malicious traffic at the DNS and proxy layers before credential harvesting occurs.



___________________________________


## 3. Critical WAVE Reports

_No Tier 1/2 WAVE reports this week._

## 4. Cyber reporting

### 4.1 Activity metrics

| Metric                   |   Value |
|--------------------------|---------|
| Daily editions           |       6 |
| Total intelligence items |     239 |
| CVE-related items        |     191 |
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

- `/root/cyber-threat-observatory/reports/2026-11-09/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-10/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-11/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-12/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-13/infrastructure_daily_brief.md`
- `/root/cyber-threat-observatory/reports/2026-11-14/infrastructure_daily_brief.md`

### 6.2 Community notes

_Placeholder for member submissions._

---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine