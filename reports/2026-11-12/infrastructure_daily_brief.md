# **Infrastructure Daily Brief: 2026-11-12**

**Infrastructure Daily Report TLP:GREEN Alert Id: c93a52ca 2026-11-13 12:36:44**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-111552 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-116335 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-120868 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-124005 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-127046 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-127111 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-127121 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-127131 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-127204 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-19422 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-111433 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-114556 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-120150 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-13672 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-18596 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-47259 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-47711 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-85101 (Tier 2)                                                          | 3.k      |
| Threats    | The hidden network: Inside the phishing infrastructure ecosystem powering global | 1.a      |
| Threats    | Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Se | 1.b      |
| Threats    | The Hidden Relay: Inside a Device Code Phishing Kit That Never Shows the Code    | 1.c      |
| Threats    | Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365  | 1.b      |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US        | 1.d      |
| Threats    | Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog | 1.e      |
| Threats    | Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK                      | 1.f      |
| Threats    | Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog     | 1.g      |
| Threats    | CVE-2026-126259                                                                  | 1.b      |
| Threats    | CVE-2026-126253                                                                  | 1.b      |
| Threats    | CVE-2026-120869                                                                  | 1.b      |
| Threats    | CVE-2026-126251                                                                  | 1.b      |
| Threats    | CVE-2026-126777                                                                  | 1.b      |
| Threats    | CVE-2026-126157                                                                  | 1.b      |
| Threats    | CVE-2026-126150                                                                  | 1.b      |
| Threats    | CVE-2026-126257                                                                  | 1.b      |
| Threats    | CVE-2026-126241                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)**

**PIR: 1.a**

Source: ketch Published: 2026-11-12

Analyzes the underground infrastructure supporting large-scale phishing operations, detailing domain generation algorithms, bulletproof hosting networks, and CDN abuse tactics. Provides actionable IOCs and architectural insights for network defenders to block malicious traffic at the DNS and proxy layers before credential harvesting occurs.

___________________________________


# **[Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)**

**PIR: 1.b**

Source: ketch Published: 2026-11-12

Dissects the EvilTokens framework, which exploits OAuth device code flows to bypass traditional MFA. Explains how attackers automate token exchange and session persistence, offering detection strategies for identity teams to monitor anomalous device code requests and implement conditional access policies.

___________________________________


# **[The Hidden Relay: Inside a Device Code Phishing Kit That Never Shows the Code](https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code)**

**PIR: 1.c**

Source: ketch Published: 2026-11-12

Reveals a novel device code phishing kit that operates without displaying the verification code to victims, using background relay techniques to capture tokens. Details the attack chain, infrastructure footprint, and evasion methods. Provides actionable detection logic for SIEM and identity protection platforms.

___________________________________


# **[Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts](https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts)**

**PIR: 1.b**

Source: ketch Published: 2026-11-12

Examines the Wazza phishing kit, a newly identified tool targeting Microsoft 365 via device code authentication. Highlights its evasion techniques, infrastructure patterns, and user interface cloning methods. Recommends endpoint and identity monitoring controls to detect and mitigate unauthorized device code approvals.

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.d**

Source: ketch Published: 2026-11-12

Explores the shift from password harvesting to device code phishing as a primary identity takeover vector. Discusses attacker motivations, campaign mechanics, and the limitations of traditional email security. Outlines defense-in-depth strategies focusing on user training, conditional access, and real-time identity analytics.

___________________________________


# **[Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog](https://www.reversinglabs.com/blog/device-code-phishing-campaign)**

**PIR: 1.e**

Source: ketch Published: 2026-11-12

Documents a widespread campaign that circumvents traditional password theft by targeting the OAuth device code flow. Explains how attackers leverage legitimate authentication endpoints to steal access tokens. Recommends network segmentation, conditional access rules, and user awareness training to mitigate identity compromise.

___________________________________


# **[Tracking BigBear 2.0 Evilginx2 Phishing Campaign | CloudSEK](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)**

**PIR: 1.f**

Source: ketch Published: 2026-11-12

Chronicles the BigBear 2.0 campaign leveraging Evilginx2 for reverse proxy phishing. Details how the toolkit intercepts multi-factor authentication challenges and session cookies. Provides network-level detection rules and proxy configuration hardening steps to prevent credential relay attacks.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.g**

Source: ketch Published: 2026-11-12

Investigates a campaign using generative AI to craft highly personalized device code phishing lures. Analyzes how AI accelerates campaign scaling and improves social engineering success rates. Offers guidance for security teams to implement AI-aware detection models and strengthen identity verification workflows.

___________________________________


# **[CVE-2026-126259](https://nvd.nist.gov/vuln/detail/CVE-2026-126259)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-11

A missing authentication for critical function vulnerability in Fortinet FortiOS 8.0.0, FortiOS 7.6.0 through 7.6.7, FortiOS 7.4.0 through 7.4.12, FortiOS 7.2.0 through 7.2.13 may allow an unauthenticated attacker with HA FGSP + standalone-config-sync, or autoscale to execute command as super admin via crafted HA packets.

___________________________________


# **[CVE-2026-126253](https://nvd.nist.gov/vuln/detail/CVE-2026-126253)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-11

A authentication bypass by primary weakness vulnerability in Fortinet FortiOS 8.0.0 through 8.0.1, FortiOS 7.6.0 through 7.6.7, FortiOS 7.4.0 through 7.4.12, FortiOS 7.2.0 through 7.2.13 may allow an unauthenticated attacker to broadcast LSA via specially crafted request

___________________________________


# **[CVE-2026-120869](https://nvd.nist.gov/vuln/detail/CVE-2026-120869)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-12

An unauthenticated attacker can bypass authentication controls to access restricted resources on the Citrix NetScaler Console appliance

___________________________________


# **[CVE-2026-126251](https://nvd.nist.gov/vuln/detail/CVE-2026-126251)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-11

A incorrect authorization vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0.3, FortiAuthenticator 6.6.0 through 6.6.10 may allow an attacker to bypass authentication and gain unauthorized access.

___________________________________


# **[CVE-2026-126777](https://nvd.nist.gov/vuln/detail/CVE-2026-126777)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-11

Traccar 3.15 before 6.17.0 contains an authentication bypass vulnerability in LdapProvider.login() that fails to reject empty passwords, causing LDAP binds to be performed as unauthenticated binds when LDAP authentication is enabled. Unauthenticated attackers who know a valid username can log in via POST /api/session or HTTP Basic authentication with an empty password against directories that permit unauthenticated binds, obtaining sessions for any account including administrators.

___________________________________


# **[CVE-2026-126157](https://nvd.nist.gov/vuln/detail/CVE-2026-126157)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-11

A improper authentication vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2 all versions may allow an unauthenticated attacker to gain access to other users' secure email accounts via crafted HTTP requests.

___________________________________


# **[CVE-2026-126150](https://nvd.nist.gov/vuln/detail/CVE-2026-126150)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-11

A weak password recovery mechanism for forgotten password vulnerability in Fortinet FortiMail 8.0.0, FortiMail 7.6.0 through 7.6.5, FortiMail 7.4.0 through 7.4.7, FortiMail 7.2.0 through 7.2.9 may allow an unauthenticated attacker to reset the password of an arbitrary IBE webmail user and take over their account via specially crafted HTTP requests.

___________________________________


# **[CVE-2026-126257](https://nvd.nist.gov/vuln/detail/CVE-2026-126257)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-11

A use of hard-coded password vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0.3, FortiAuthenticator 6.6.0 through 6.6.10 may allow an unauthenticated attacker to bypass credential validation in certain circumstances outside of the attacker's control and gain unauthorized access.

___________________________________


# **[CVE-2026-126241](https://nvd.nist.gov/vuln/detail/CVE-2026-126241)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-11-11

A improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiAuthenticator 8.0.0 through 8.0.3, FortiAuthenticator 6.6.0 through 6.6.10 may allow an authenticated attacker to execute unauthorized SQL commands on the underlying database.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-111552 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111552)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Authentication bypass in internet-facing e-commerce infrastructure directly threatens payment processing and transactional integrity, aligning with the Finance sector.

*Deep dive: `TIER_2_CVE-2026-111552.md`*

___________________________________


# **[CVE-2026-116335 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-116335)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Foundational PostgreSQL database engine with OS-level RCE risk, directly impacting Finance, Healthcare, and Government data storage and transaction systems.

*Deep dive: `TIER_2_CVE-2026-116335.md`*

___________________________________


# **[CVE-2026-120868 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120868)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Foundational edge infrastructure (Citrix NetScaler) heavily deployed across Government, Finance, and Healthcare; unauthenticated DoS directly threatens availability of regulated digital public services.

*Deep dive: `TIER_2_CVE-2026-120868.md`*

___________________________________


# **[CVE-2026-124005 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-124005)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Impacts healthcare pharmaceutical cold-chain and critical supply infrastructure via unauthenticated remote compromise of internet-exposed supervisory controllers.

*Deep dive: `TIER_2_CVE-2026-124005.md`*

___________________________________


# **[CVE-2026-127046 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127046)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Unauthenticated API key disclosure in MISP Modules, a foundational threat intelligence platform widely deployed by government and critical infrastructure operators.

*Deep dive: `TIER_2_CVE-2026-127046.md`*

___________________________________


# **[CVE-2026-127111 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127111)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Unauthenticated account takeover in widely deployed public-sector and enterprise webmail infrastructure, enabling lateral movement and data exfiltration.

*Deep dive: `TIER_2_CVE-2026-127111.md`*

___________________________________


# **[CVE-2026-127121 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127121)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Foundational groupware deployed across Government and Healthcare IT enables S/MIME certificate spoofing, compromising encrypted communications in regulated environments.

*Deep dive: `TIER_2_CVE-2026-127121.md`*

___________________________________


# **[CVE-2026-127131 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127131)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Directly impacts Digital Identity by bypassing TOTP 2FA in SOGo groupware, enabling full account takeover for public-facing enterprise and government collaboration portals.

*Deep dive: `TIER_2_CVE-2026-127131.md`*

___________________________________


# **[CVE-2026-127204 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-127204)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Finance sector: unauthenticated payment bypass in WooCommerce PayPal Pro enables fraudulent order fulfillment and direct merchant revenue loss.

*Deep dive: `TIER_2_CVE-2026-127204.md`*

___________________________________


# **[CVE-2026-19422 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19422)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Foundational DNS/DHCP/IPAM management infrastructure underpinning Healthcare, Finance, and Government digital services; internal auth bypass enables network-wide traffic redirection and service disruption.

*Deep dive: `TIER_2_CVE-2026-19422.md`*

___________________________________


# **[CVE-2026-111433 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-111433)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Container runtime flaw in openEuler iSulad enables host data exfiltration, directly impacting government and telecom infrastructure deployments.

*Deep dive: `TIER_2_CVE-2026-111433.md`*

___________________________________


# **[CVE-2026-114556 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-114556)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

General infrastructure email server widely deployed in regulated sectors (government, finance, healthcare); unauthenticated RCE risk threatens core communications.

*Deep dive: `TIER_2_CVE-2026-114556.md`*

___________________________________


# **[CVE-2026-120150 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-120150)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Foundational backend database for regulated/public services; TIER 2 RCE mandates prompt patching across enterprise and government deployments.

*Deep dive: `TIER_2_CVE-2026-120150.md`*

___________________________________


# **[CVE-2026-13672 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-13672)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

General infrastructure NAS platform widely deployed across government and enterprise environments, with an SSOAuth authorization bypass impacting data storage and access controls.

*Deep dive: `TIER_2_CVE-2026-13672.md`*

___________________________________


# **[CVE-2026-18596 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18596)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

MFA bypass on widely deployed enterprise and government NAS infrastructure enables arbitrary file access and full system compromise.

*Deep dive: `TIER_2_CVE-2026-18596.md`*

___________________________________


# **[CVE-2026-47259 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-47259)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

Impacts building automation controllers widely deployed in hospitals and government facilities, posing operational risk to critical infrastructure.

*Deep dive: `TIER_2_CVE-2026-47259.md`*

___________________________________


# **[CVE-2026-47711 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-47711)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

BACnet stack vulnerability impacts building automation systems that underpin healthcare and government facilities, posing DoS risks to critical facility management.

*Deep dive: `TIER_2_CVE-2026-47711.md`*

___________________________________


# **[CVE-2026-85101 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-85101)**

**PIR: 3.k**

Source: WAVE Published: 2026-11-12

TIER 2 authentication bypass in Synology DSM rsync service; impacts foundational NAS infrastructure widely deployed in government and enterprise backup environments.

*Deep dive: `TIER_2_CVE-2026-85101.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine