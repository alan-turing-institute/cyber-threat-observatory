# **Infrastructure Daily Brief: 2026-11-14**

**Infrastructure Daily Report TLP:GREEN Alert Id: 222bf6cc 2026-11-15 06:46:32**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-129456 (Tier 2)                                                         | 3.k      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.a      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.a      |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass           | 1.a      |
| Threats    | Device code phishing bypasses password stealing                                  | 1.a      |
| Threats    | Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and | 1.b      |
| Threats    | Device Code Phishing: An Evolving Technique Impacting SLTTs                      | 1.a      |
| Threats    | Russian hackers can steal government emails without victims clicking a link, cyb | 1.c      |
| Threats    | Russian APT Exploits Zimbra XSS to Target Ukraine Government                     | 1.c      |
| Threats    | CVE-2026-129110                                                                  | 1.b      |
| Threats    | CVE-2026-126310                                                                  | 1.b      |
| Threats    | CVE-2026-107413                                                                  | 1.b      |
| Threats    | CVE-2026-111342                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Device Code Phishing is an Evolution in Identity Takeover](https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.a**

Source: ketch Published: 2026-11-14

Explores how attackers leverage OAuth device code flows to bypass traditional MFA controls. Defenders must monitor for anomalous device code authorization requests and implement conditional access policies that restrict device code usage to trusted networks and applications.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.a**

Source: ketch Published: 2026-11-14

Details a campaign using AI-generated lures to trick users into entering device codes. Highlights the need for enhanced user training, AI-driven threat detection, and strict conditional access rules to mitigate automated identity takeover attempts targeting enterprise cloud environments.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.a**

Source: ketch Published: 2026-11-14

Analyzes the technical mechanics of device code phishing, demonstrating how convenience features in modern authentication protocols can be weaponized. Recommends infrastructure defenders disable unnecessary device code flows, enforce step-up authentication, and deploy real-time alerting for suspicious authorization patterns.

___________________________________


# **[Device code phishing bypasses password stealing](https://reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.a**

Source: ketch Published: 2026-11-14

Examines how threat actors shift from credential harvesting to direct session and token theft via device code prompts. Provides actionable mitigation strategies for IT teams, including monitoring OAuth token issuance, implementing phishing-resistant MFA, and restricting device code scopes in identity providers.

___________________________________


# **[Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA](https://cisa.gov/uscert/ncas/alerts/aa21-148a)**

**PIR: 1.b**

Source: ketch Published: 2026-11-14

CISA alert detailing a coordinated spearphishing operation using malicious attachments and links to deploy credential harvesters. Advises defenders to implement email filtering rules, monitor for known IOCs, and enforce strict access controls to protect critical infrastructure and sensitive communications.

___________________________________


# **[Device Code Phishing: An Evolving Technique Impacting SLTTs](https://cisecurity.org/insights/blog/device-code-phishing-evolving-technique-impacting-sltts)**

**PIR: 1.a**

Source: ketch Published: 2026-11-14

Focuses on the impact of device code phishing on state, local, tribal, and territorial governments. Offers infrastructure-specific guidance for securing identity platforms, hardening conditional access policies, and establishing incident response playbooks tailored to public sector cloud environments.

___________________________________


# **[Russian hackers can steal government emails without victims clicking a link, cyber agencies warn](https://nextgov.com/cybersecurity/2026/07/russian-hackers-can-steal-government-emails-without-victims-clicking-link-cyber-agencies-warn/414967)**

**PIR: 1.c**

Source: ketch Published: 2026-11-14

Warns of drive-by credential theft techniques exploiting email client vulnerabilities and server-side flaws. Recommends infrastructure teams prioritize zero-trust email architectures, enforce strict authentication protocols, and continuously monitor for unauthorized access patterns across government networks.

___________________________________


# **[Russian APT Exploits Zimbra XSS to Target Ukraine Government](http://web.archive.org/web/20260320065313/https:/www.seqrite.com/blog/operation-ghostmail-zimbra-xss-russian-apt-ukraine)**

**PIR: 1.c**

Source: ketch Published: 2026-11-14

Documents an APT campaign leveraging a cross-site scripting vulnerability in Zimbra email servers to intercept credentials and session tokens. Highlights the importance of patching legacy email infrastructure, deploying web application firewalls, and monitoring for anomalous authentication traffic.

___________________________________


# **[CVE-2026-129110](https://nvd.nist.gov/vuln/detail/CVE-2026-129110)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-13

sysPass 3.0.1 through 3.2.11 contains an authentication bypass vulnerability that allows unauthenticated attackers to reinstall an already-installed instance by POSTing to the install/install handler, which never checks isInstalled(). Attackers can overwrite config.xml, point the application at an attacker-controlled database, create an administrator account, and plant serialized PublicLink gadget chains triggered via account/viewLink to execute commands.

___________________________________


# **[CVE-2026-126310](https://nvd.nist.gov/vuln/detail/CVE-2026-126310)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-13

OpenBao before 2.6.5 and 2.7.2 contains an authentication bypass vulnerability that allows unauthenticated callers to obtain OIDC ID tokens by abusing public clients with client_credentials enabled. Attackers who know a public client's client_id can request tokens from the identity/oidc/provider/<name>/token endpoint to impersonate the client without any secret.

___________________________________


# **[CVE-2026-107413](https://nvd.nist.gov/vuln/detail/CVE-2026-107413)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-13

Memory overflow in SAML authentication can lead to unpredictable or erroneous behavior or Denial of Service in Citrix NetScaler ADC and Citrix NetScaler Gateway.

___________________________________


# **[CVE-2026-111342](https://nvd.nist.gov/vuln/detail/CVE-2026-111342)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-13

Memory overflow in LDAP authentication can lead to unpredictable or erroneous behavior or Denial of Service in Citrix NetScaler ADC and Citrix NetScaler Gateway.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-129456 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-129456)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-14

Foundational BGP routing software (FRRouting) widely deployed across ISP, government, finance, and healthcare networks; DoS/RCE potential disrupts critical internet routing infrastructure.

*Deep dive: `TIER_2_CVE-2026-129456.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine