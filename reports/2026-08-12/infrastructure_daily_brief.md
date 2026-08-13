# **Infrastructure Daily Brief: 2026-08-12**

**Infrastructure Daily Report TLP:GREEN Alert Id: 1c7ca639 2026-08-13 19:40:59**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                          | PIR(s)   |
|------------|---------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-11923 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-12359 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-13267 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-16860 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-26035 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-49473 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-71193 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73289 (Tier 2)                                                         | 3.k      |
| Cyber News | CVE-2026-73418 (Tier 2)                                                         | 3.k      |
| Threats    | OAuth Device Code Phishing: 37x Surge in Enterprise ATO                         | 1.b      |
| Threats    | The Device Code Phishing Tsunami: What We’re Seeing in the Wild                 | 1.b.2    |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass          | 1.b.3    |
| Threats    | The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave    | 1.e      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns               | 1.c      |
| Threats    | The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations        | 1.d      |
| Threats    | Hackers Hijack 20+ Government Websites to Deliver Malware Through Trusted Links | 1.f      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                 | 1.g      |
| Threats    | CVE-2026-72920                                                                  | 1.b      |
| Threats    | CVE-2026-12571                                                                  | 1.b      |
| Threats    | CVE-2026-72537                                                                  | 1.b      |
| Threats    | CVE-2026-72534                                                                  | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[OAuth Device Code Phishing: 37x Surge in Enterprise ATO](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf)**

**PIR: 1.b**

Source: ketch Published: 2026-08-12

This Cloud Security Alliance report details a 37-fold increase in enterprise account takeovers leveraging OAuth device code flows. Attackers bypass traditional MFA by tricking users into entering short-lived codes on compromised devices. Infrastructure defenders must monitor for anomalous OAuth consent requests, restrict device code grant types in identity providers, and implement conditional access policies that validate device posture alongside code validation.

___________________________________


# **[The Device Code Phishing Tsunami: What We’re Seeing in the Wild](https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild)**

**PIR: 1.b.2**

Source: ketch Published: 2026-08-12

Level Blue’s SpiderLabs analyzes real-world device code phishing campaigns targeting enterprise SaaS platforms. The report highlights how attackers automate code collection via fake login portals and leverage legitimate OAuth endpoints to authenticate. Defenders should deploy URL filtering for known phishing domains, enforce strict OAuth client registration, and educate users on recognizing device code prompts versus standard login flows.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://trendmicro.com/en/research/26/g/device-code-phishing.html)**

**PIR: 1.b.3**

Source: ketch Published: 2026-08-12

Trend Micro examines how device code authentication, designed for screenless devices, is weaponized to circumvent multi-factor authentication. Attackers host spoofed portals requesting codes, which are instantly validated against legitimate identity providers. IT infrastructure teams must audit OAuth configurations, disable unnecessary device code grants, and implement behavioral analytics to detect rapid code redemption patterns indicative of automated phishing.

___________________________________


# **[The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave](https://slashid.com/blog/illicit-consent-grant-part-2)**

**PIR: 1.e**

Source: ketch Published: 2026-08-12

SlashID explores the convergence of illicit consent grants, device code phishing, and AI-driven Phishing-as-a-Service platforms. The analysis reveals how attackers combine automated infrastructure provisioning with social engineering to harvest OAuth tokens. Defenders should enforce strict consent screen policies, monitor for newly registered OAuth applications, and integrate threat intelligence feeds to block AI-generated phishing domains at the DNS level.

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.c**

Source: ketch Published: 2026-08-12

CYFIRMA investigates how threat actors leverage cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. This approach evades traditional IP-based blocking and scales rapidly. Infrastructure defenders must implement cloud security posture management, monitor for anomalous resource creation patterns, and enforce strict egress filtering to prevent compromised workloads from serving malicious content.

___________________________________


# **[The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations](https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations)**

**PIR: 1.d**

Source: ketch Published: 2026-08-12

This report outlines the shift from manual phishing campaigns to fully autonomous AI-driven operations. Machine learning models now generate context-aware lures, manage infrastructure lifecycles, and adapt to security controls in real time. Defenders must prioritize AI-enhanced email security gateways, deploy deception technology to feed false data to AI models, and establish continuous monitoring for automated credential harvesting attempts.

___________________________________


# **[Hackers Hijack 20+ Government Websites to Deliver Malware Through Trusted Links](https://cybersecuritynews.com/government-websites-deliver-malware/amp)**

**PIR: 1.f**

Source: ketch Published: 2026-08-12

Cybercriminals compromise legitimate government domains to host phishing pages and malware distribution links, exploiting user trust in official URLs. The attack bypasses reputation-based filtering and email security controls. Infrastructure teams should implement strict web application firewalls, enforce domain integrity checks via DNSSEC, and deploy browser isolation solutions to sandbox interactions with high-trust domains that exhibit anomalous behavior.

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.g**

Source: ketch Published: 2026-08-12

CISA alerts on a zero-click phishing campaign targeting Zimbra email clients, exploiting rendering vulnerabilities to execute malicious scripts without user interaction. The attack harvests credentials and session tokens directly from the email client. Defenders must prioritize patching Zimbra instances, disable auto-rendering of external content, and implement network segmentation to limit lateral movement if email clients are compromised.

___________________________________


# **[CVE-2026-72920](https://nvd.nist.gov/vuln/detail/CVE-2026-72920)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-11

SeaweedFS is a distributed storage system. Prior to 4.24, the filer registers the SeaweedIdentityAccessManagement gRPC service without mandatory authentication when jwt.filer_signing.key is unset, allowing any client that can reach the filer gRPC port to invoke CreateUser, CreateAccessKey, PutPolicy, and related IAM RPCs to mint credentials and gain S3 administrative control. This issue is fixed in versions 4.24.

___________________________________


# **[CVE-2026-12571](https://nvd.nist.gov/vuln/detail/CVE-2026-12571)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-11

An authentication bypass in ManageEngine DDI Central's password-reset workflow allows account takeover.

___________________________________


# **[CVE-2026-72537](https://nvd.nist.gov/vuln/detail/CVE-2026-72537)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-11

A privilege escalation vulnerability in Authentik Security authentik through 2026.5.6 allows an attacker with a source-scoped SCIM provisioning token to take over any user account including superusers by provisioning a SCIM user that matches an existing local user by username. The SCIM user ingest function adopts pre-existing local accounts by username without validating scope boundaries. An attacker can rewrite or delete any account, including the superuser, using only a limited provisioning cr

___________________________________


# **[CVE-2026-72534](https://nvd.nist.gov/vuln/detail/CVE-2026-72534)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-08-11

A privilege escalation vulnerability in Authentik Security authentik through 2026.5.6 allows an attacker with a source-scoped SCIM provisioning token to gain superuser privileges by provisioning a SCIM group that matches an existing administrator group by name. The SCIM group ingest function adopts any existing group by name and replaces its membership without validating the source scope against the target group. An attacker can grant their provisioning token full IdP superuser access and lock o

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-11923 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-11923)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-12

Directly impacts enterprise IAM gateways and reverse proxies, enabling potential authentication bypass and token forgery in public-facing Digital Identity deployments.

*Deep dive: `TIER_2_CVE-2026-11923.md`*

___________________________________


# **[CVE-2026-12359 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-12359)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-12

Enterprise IAM reverse proxy flaw enabling unauthenticated sensitive data exposure, directly impacting the Digital Identity sector and public-facing authentication perimeters.

*Deep dive: `TIER_2_CVE-2026-12359.md`*

___________________________________


# **[CVE-2026-13267 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-13267)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-12

Directly impacts the Digital Identity sector by compromising core IAM gateways, enabling authenticated privilege escalation and bypassing authorization controls for public-facing services.

*Deep dive: `TIER_2_CVE-2026-13267.md`*

___________________________________


# **[CVE-2026-16860 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-16860)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-12

Foundational enterprise OS (IBM i) critical to Finance, Government, and Healthcare backend processing; RCE requires auth but impacts core transaction/record systems.

*Deep dive: `TIER_2_CVE-2026-16860.md`*

___________________________________


# **[CVE-2026-26035 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-26035)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-12

Critical WAF authentication bypass in foundational edge security infrastructure explicitly tied to protecting Digital Identity, Finance, Healthcare, and Government public-facing services.

*Deep dive: `TIER_2_CVE-2026-26035.md`*

___________________________________


# **[CVE-2026-49473 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-49473)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-12

Authorization bypass in a widely used policy middleware undermines identity-aware access controls in public-facing web applications and APIs.

*Deep dive: `TIER_2_CVE-2026-49473.md`*

___________________________________


# **[CVE-2026-71193 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-71193)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-12

Cross-tenant DNS isolation bypass in OpenStack Designate threatens multi-tenant cloud deployments underpinning Government, Finance, and Healthcare DPI services.

*Deep dive: `TIER_2_CVE-2026-71193.md`*

___________________________________


# **[CVE-2026-73289 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73289)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-12

IAM policy evaluation flaw breaks JWT/OIDC group and role enforcement in distributed object storage, directly impacting Digital Identity and Government data sovereignty deployments.

*Deep dive: `TIER_2_CVE-2026-73289.md`*

___________________________________


# **[CVE-2026-73418 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-73418)**

**PIR: 3.k**

Source: WAVE Published: 2026-08-12

Core Digital Identity/IdAM library (NextAuth.js) handling OAuth/OIDC sessions and tokens; trivial unauthenticated DoS impacts public-facing authentication endpoints.

*Deep dive: `TIER_2_CVE-2026-73418.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine