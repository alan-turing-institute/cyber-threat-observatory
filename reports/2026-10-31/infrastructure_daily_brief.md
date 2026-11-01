# **Infrastructure Daily Brief: 2026-10-31**

**Infrastructure Daily Report TLP:GREEN Alert Id: 94015d92 2026-11-01 02:13:15**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-119977 (Tier 2)                                                         | 3.k      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing                | 1.j.3    |
| Threats    | Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM | 1.j.3    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.j.3    |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.j.3    |
| Threats    | MadApe: The Code That Opens the Door                                             | 1.j.3    |
| Threats    | The ‘code of conduct’ phishing campaign: What MSPs need to know right now        | 1.a      |
| Threats    | Joint advisory: state-sponsored spear-phishing campaigns targeting critical infr | 1.a      |
| Threats    | Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Atta | 1.d      |
| Threats    | CVE-2026-63377                                                                   | 1.b      |
| Threats    | CVE-2026-116239                                                                  | 1.b      |
| Threats    | CVE-2026-63378                                                                   | 1.b      |
| Threats    | CVE-2026-115830                                                                  | 1.b      |
| Threats    | CVE-2026-115829                                                                  | 1.b      |
| Threats    | CVE-2026-119572                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Unmasking EvilTokens: Getting to the root of device code phishing](https://aka.ms/EvilTokens-PhaaS)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-31

Analyzes the EvilTokens framework, detailing how attackers exploit OAuth device code flows to bypass MFA and steal valid authentication tokens. Provides technical breakdowns of the phishing infrastructure, proxy configurations, and mitigation strategies for identity administrators managing enterprise access controls.

___________________________________


# **[Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise](https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-31

Details a sophisticated multi-stage campaign leveraging fake compliance portals to deploy Adversary-in-the-Middle proxies. Explains how attackers capture session cookies and tokens in real-time, offering detection rules, conditional access tuning, and architectural defenses for enterprise identity platforms.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-31

Explores how device code phishing has matured into a primary vector for identity takeover, circumventing traditional MFA controls. Discusses threat actor infrastructure, user interaction patterns, and strategic controls like token lifetime restrictions and OAuth consent monitoring for infrastructure defenders.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-31

Investigates a campaign leveraging generative AI to craft highly personalized lures that drive victims to device code authentication prompts. Analyzes AI-generated content patterns, infrastructure scaling, and identity-centric detection strategies to neutralize automated phishing operations targeting cloud environments.

___________________________________


# **[MadApe: The Code That Opens the Door](https://group-ib.com/blog/madape-microsoft-device-code-phishing-kit)**

**PIR: 1.j.3**

Source: ketch Published: 2026-10-31

Reverse-engineers the MadApe phishing kit, revealing its automated infrastructure for harvesting Microsoft device codes. Covers deployment mechanics, proxy configurations, and actionable telemetry for SOC teams to block kit-hosted domains and monitor for anomalous OAuth consent events across tenant networks.

___________________________________


# **[The ‘code of conduct’ phishing campaign: What MSPs need to know right now](https://blog.barracuda.com/2026/05/07/code-of-conduct-phishing-campaign-msp-response)**

**PIR: 1.a**

Source: ketch Published: 2026-10-31

Examines the operational tactics behind the widespread compliance-themed phishing wave targeting managed service providers. Highlights infrastructure-level indicators, email filtering bypass techniques, and recommended response playbooks for MSP security teams managing multi-tenant client environments.

___________________________________


# **[Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT](https://suvat.uk/blog/five-eyes-advisory.html)**

**PIR: 1.a**

Source: ketch Published: 2026-10-31

Five Eyes joint advisory outlining state-sponsored spearphishing operations targeting critical infrastructure sectors. Covers campaign infrastructure, initial access tactics, and cross-agency recommendations for network segmentation, email security posture, and incident response coordination for high-value assets.

___________________________________


# **[Foreign Threat Actor Conducting Large-Scale Spearphishing Campaign with RDP Attachments | CISA](https://www.cisa.gov/news-events/alerts/2024/10/31/foreign-threat-actor-conducting-large-scale-spearphishing-campaign-rdp-attachments)**

**PIR: 1.d**

Source: ketch Published: 2026-10-31

CISA alert on a large-scale campaign distributing malicious RDP files to establish remote access. Details file characteristics, execution chains, and defensive measures including attachment filtering, RDP hardening, and endpoint detection rules for infrastructure teams managing hybrid workloads.

___________________________________


# **[CVE-2026-63377](https://nvd.nist.gov/vuln/detail/CVE-2026-63377)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

TAKO AI Agent for Okta is a local-first AI agent that helps Okta administrators query tenant data using natural language. Prior to 3.0.1-beta, `POST /api/auth/setup` in `src/api/routers/auth.py` allows an unauthenticated network attacker to create the first administrator account before the legitimate owner completes initial setup. The `initial_setup` function checks only the `is_setup` completion flag and requires no authentication, one-time bootstrap token, or network restriction. The default `

___________________________________


# **[CVE-2026-116239](https://nvd.nist.gov/vuln/detail/CVE-2026-116239)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

In server mode pgAdmin 4 keeps an account per authentication source, so the same username can exist as, for example, an internal account and an LDAP account. After LDAP or Kerberos authenticated a user, pgAdmin chose the account to log in by username alone, or took the account Flask-Security's login form had looked up, without checking that it came from the source that authenticated the user. The session therefore belonged to another account, with its role, its servers and its saved database pas

___________________________________


# **[CVE-2026-63378](https://nvd.nist.gov/vuln/detail/CVE-2026-63378)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

TAKO AI Agent for Okta is a local-first AI agent that helps Okta administrators query tenant data using natural language. Prior to 3.0.1-beta, any authenticated user with a valid `fctr_session` cookie can submit arbitrary Python source in the `script_code` field of `POST /api/react/execute-script`, without administrator privilege. In `src/api/routers/react_stream.py`, the source is stored with `skip_discovery=True`, bypassing AI-based content filtering, and is passed to `validate_generated_code`

___________________________________


# **[CVE-2026-115830](https://nvd.nist.gov/vuln/detail/CVE-2026-115830)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

In Secret Server versions earlier than 12.3.1, a user under certain conditions could submit an unsigned JWT and receive cloudadmin permissions in response.

___________________________________


# **[CVE-2026-115829](https://nvd.nist.gov/vuln/detail/CVE-2026-115829)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

In Secret Server versions earlier than 12.3.1, a user could bypass the initial login step and authenticate by successfully negotiating the second factor login step only.

___________________________________


# **[CVE-2026-119572](https://nvd.nist.gov/vuln/detail/CVE-2026-119572)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-30

Traefik from 3.7.0-ea.1 before 3.7.15 contains an authentication bypass vulnerability in the Kubernetes Ingress NGINX provider that silently disables mTLS configured via the auth-tls-secret annotation. When another Ingress declares a path on the same host without matching auth-tls settings, Traefik falls back to default TLS options, letting unauthenticated attackers reach backends requiring client certificates.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-119977 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-119977)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-31

General infrastructure RCE in widely deployed WordPress CMS, explicitly noted as impacting government, healthcare, and finance public-facing sites.

*Deep dive: `TIER_2_CVE-2026-119977.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine