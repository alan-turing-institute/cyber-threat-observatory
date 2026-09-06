# **Infrastructure Daily Brief: 2026-09-05**

**Infrastructure Daily Report TLP:GREEN Alert Id: e1d84364 2026-09-06 04:10:19**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-67276 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-67281 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-86060 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-67277 (Tier 2)                                                          | 3.k      |
| Threats    | Inside an AI‑enabled device code phishing campaign                               | 1.b.2    |
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave     | 1.e.2    |
| Threats    | A New Era Of Social Engineering: The Device Code Phishing Boom                   | 1.b.1    |
| Threats    | Device Code Phishing — The Attack That Makes MFA Irrelevant                      | 1.b.2    |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                  | 1.b.1    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                        | 1.e.1    |
| Threats    | Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing            | 1.g.1    |
| Threats    | Massive “TrustTrap” Phishing Campaign Exploits Human Perception, Targets Governm | 1.f.1    |
| Threats    | CVE-2026-75754                                                                   | 1.b      |
| Threats    | CVE-2026-85595                                                                   | 1.b      |
| Threats    | CVE-2026-86117                                                                   | 1.b      |
| Threats    | CVE-2026-9317                                                                    | 1.b      |
| Threats    | CVE-2026-85596                                                                   | 1.b      |
| Threats    | CVE-2026-18221                                                                   | 1.b      |
| Threats    | CVE-2026-53603                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.b.2**

Source: ketch Published: 2026-09-05

Microsoft details a sophisticated phishing campaign leveraging AI-driven infrastructure to automate device code requests. Unlike traditional static scripts, this threat actor utilizes end-to-end automation to bypass multi-factor authentication, marking a significant escalation in operational sophistication. Infrastructure defenders should monitor OAuth consent logs and implement conditional access policies to mitigate automated credential harvesting.

___________________________________


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.e.2**

Source: ketch Published: 2026-09-05

SlashID explores the convergence of illicit OAuth consent grants and AI-powered phishing-as-a-service. The analysis highlights how threat actors abuse device code flows to silently harvest identity tokens without user interaction. Defenders must audit third-party application permissions, enforce strict consent policies, and deploy identity threat detection to block automated token theft.

___________________________________


# **[A New Era Of Social Engineering: The Device Code Phishing Boom](https://coalitioninc.com/blog/security-labs/a-new-era-of-social-engineering-the-device-code-phishing-boom)**

**PIR: 1.b.1**

Source: ketch Published: 2026-09-05

Coalition Inc. examines the rapid proliferation of device code phishing as a primary vector for identity compromise. The report outlines how attackers combine social engineering with automated infrastructure to target enterprise users. IT teams are advised to disable unnecessary device code flows, educate users on QR code verification prompts, and integrate identity analytics for real-time anomaly detection.

___________________________________


# **[Device Code Phishing — The Attack That Makes MFA Irrelevant](https://cybergrind.org/blog/2026-06-02-device-code-phishing)**

**PIR: 1.b.2**

Source: ketch Published: 2026-09-05

CyberGrind breaks down how device code phishing effectively neutralizes traditional MFA controls by leveraging legitimate authentication endpoints. The article provides technical indicators of compromise and mitigation strategies for infrastructure teams. Recommendations include implementing phishing-resistant MFA, monitoring for rapid sequential device code approvals, and restricting OAuth scopes to limit lateral movement.

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.b.1**

Source: ketch Published: 2026-09-05

LevelBlue shares real-world telemetry from active device code phishing campaigns targeting cloud infrastructure. The analysis reveals patterns in domain registration, hosting infrastructure, and user targeting tactics. Defenders can leverage these insights to update firewall rules, block malicious OAuth redirect URIs, and enhance SIEM correlation rules for suspicious consent grant activities.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.e.1**

Source: ketch Published: 2026-09-05

Proofpoint traces the evolution of identity takeover attacks, highlighting device code phishing as a critical inflection point. The report details how attackers pivot from credential stuffing to consent-based authentication abuse. Infrastructure defenders should prioritize zero-trust identity architectures, enforce just-in-time access, and deploy behavioral analytics to detect anomalous login patterns across hybrid environments.

___________________________________


# **[Operation HookedWing: 4-Year Campaign Compromises 500 Orgs - Phishing](https://dailysecurityreview.com/phishing/operation-hookedwing-4-year-campaign-compromises-500-orgs/)**

**PIR: 1.g.1**

Source: ketch Published: 2026-09-05

Daily Security Review investigates a persistent, multi-year phishing campaign that successfully infiltrated over 500 organizations. The operation utilized customized lures and infrastructure hopping to evade detection. IT defenders should review historical email logs, assess third-party vendor access, and implement advanced email security gateways with AI-driven threat classification to prevent similar long-term compromises.

___________________________________


# **[Massive “TrustTrap” Phishing Campaign Exploits Human Perception, Targets Government Services Across US, India, and Beyond](https://cyberp1.com/massive-trusttrap-phishing-campaign-exploits-human-perception-targets-government-services-across-us-india-and-beyond/)**

**PIR: 1.f.1**

Source: ketch Published: 2026-09-05

CyberP1 analyzes the TrustTrap campaign, which weaponizes cognitive biases and realistic UI cloning to target government and critical infrastructure sectors. The attack chain relies on psychological manipulation rather than technical exploits. Defenders should enhance user awareness training, deploy browser isolation for high-risk links, and monitor for anomalous access patterns from geographically inconsistent locations.

___________________________________


# **[CVE-2026-75754](https://nvd.nist.gov/vuln/detail/CVE-2026-75754)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

Missing Authentication for Critical Function, Server-Side Request Forgery (SSRF), and Use of Hard-coded Credentials in ASUS Control Center allow an unauthorized user to obtain the encryption key via an HTTP request, causing a local service to enable SSH on port 2222. The attacker can then log in with the hardcode credentials to obtain a root shell, enabling direct reading, writing, and deletion of data on ASUS Control Center, as well as remote control of all servers, PCs, and workstations within

___________________________________


# **[CVE-2026-85595](https://nvd.nist.gov/vuln/detail/CVE-2026-85595)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

Traefik versions before v2.11.55 contain an authentication bypass vulnerability in the digestAuth middleware where unknown usernames receive an empty secret instead of rejection. Attackers can compute a valid digest response using the empty secret and arbitrary credentials to bypass authentication on any digestAuth-protected route without a valid username or password.

___________________________________


# **[CVE-2026-86117](https://nvd.nist.gov/vuln/detail/CVE-2026-86117)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-05

Coolify through 4.3.17 contains an authentication bypass vulnerability in the OAuth callback handler that signs users into existing accounts based solely on email address without verifying provider assertions or binding OAuth identities. Attackers can register a victim's email address on any enabled OAuth provider to obtain authenticated sessions as that user, bypassing password requirements and two-factor authentication.

___________________________________


# **[CVE-2026-9317](https://nvd.nist.gov/vuln/detail/CVE-2026-9317)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

Nango before 0.71.6 contains a missing authentication vulnerability in the runner tRPC server that allows unauthenticated attackers to execute arbitrary JavaScript code by invoking the exposed start procedure without credentials. Attackers with network access to the runner port can send requests to the unauthenticated start procedure, bypassing the unenforced RUNNER_SECRET_KEY environment variable, to achieve remote code execution within the runner process.

___________________________________


# **[CVE-2026-85596](https://nvd.nist.gov/vuln/detail/CVE-2026-85596)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

Traefik versions >= v3.7.0 and <= v3.7.10 contain an authentication bypass in the Kubernetes Ingress NGINX provider. The TLS option generated for an Ingress carrying the nginx.ingress.kubernetes.io/auth-tls-secret annotation was named after the Ingress namespace and name. As a result, two Ingress objects sharing the same host, the same client CA secret, and the same client-authentication mode produced two distinct TLS option names for that host. Traefik treats this as a TLS options conflict and 

___________________________________


# **[CVE-2026-18221](https://nvd.nist.gov/vuln/detail/CVE-2026-18221)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

IBM i 7.6, 7.5, 7.4, and 7.3 could allow a remote attacker to gain unauthorized access due to improper validation of client-supplied authentication parameters.

___________________________________


# **[CVE-2026-53603](https://nvd.nist.gov/vuln/detail/CVE-2026-53603)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-04

nebula-mesh is a self-hosted control plane for Slack Nebula mesh VPN. Prior to version 0.3.8, Operator session tokens are stored in plaintext in the operator_sessions table (the token column is the PRIMARY KEY). The session token is a 32-byte random hex value sent directly in a cookie and valid for 24 hours. Anyone who can read the database (backup, snapshot, file copy, or SQL-level disclosure) obtains every active session token and can hijack operator sessions directly, with no further authenti

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-67276 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67276)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-05

Actively exploited SSH authentication bypass in MikroTik RouterOS, a foundational edge routing platform widely deployed across government networks, municipal infrastructure, and ISP backbones.

*Deep dive: `TIER_2_CVE-2026-67276.md`*

___________________________________


# **[CVE-2026-67281 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67281)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-05

Foundational telecom/edge routing infrastructure with unauthenticated credential exposure, explicitly impacting ISPs and government networks.

*Deep dive: `TIER_2_CVE-2026-67281.md`*

___________________________________


# **[CVE-2026-86060 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-86060)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-05

Actively exploited privilege escalation in MikroTik RouterOS, a foundational network infrastructure platform widely deployed across government, enterprise, and ISP environments.

*Deep dive: `TIER_2_CVE-2026-86060.md`*

___________________________________


# **[CVE-2026-67277 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-67277)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-05

Foundational edge routing and firewall infrastructure widely deployed across public and enterprise networks, with unauthenticated remote DoS and memory disclosure impacting service availability.

*Deep dive: `TIER_2_CVE-2026-67277.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine