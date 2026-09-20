# **Infrastructure Daily Brief: 2026-09-16**

**Infrastructure Daily Report TLP:GREEN Alert Id: d5337f32 2026-09-20 09:35:25**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                           | PIR(s)   |
|------------|----------------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-18212 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20192 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20194 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20237 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-74909 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76423 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-76460 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-79651 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-80274 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-81642 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-92794 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-19667 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-89783 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-90049 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-92804 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20329 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20330 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-20333 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-77692 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-82399 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-89775 (Tier 2)                                                          | 3.k      |
| Cyber News | CVE-2026-70416 (Tier 2)                                                          | 3.k      |
| Threats    | GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Secon | 1.d      |
| Threats    | Microsoft 365: Block Device Code Flow Against GhostCode                          | 1.d      |
| Threats    | Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI  | 1.h      |
| Threats    | Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA                  | 1.f      |
| Threats    | Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA      | 1.e      |
| Threats    | Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining S | 1.d      |
| Threats    | Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncove | 1.g      |
| Threats    | PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted | 1.g      |
| Threats    | CVE-2026-83059                                                                   | 1.b      |
| Threats    | CVE-2026-71133                                                                   | 1.b      |
| Threats    | CVE-2026-92808                                                                   | 1.b      |
| Threats    | CVE-2026-20234                                                                   | 1.b      |
| Threats    | CVE-2026-62379                                                                   | 1.b      |
| Threats    | CVE-2026-83066                                                                   | 1.b      |
| Threats    | CVE-2026-83062                                                                   | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds](https://cybersecuritynews.com/ghostcode-phishing-kit/amp)**

**PIR: 1.d**

Source: ketch Published: 2026-09-16

Threat actors are deploying the GhostCode phishing kit to rapidly bypass Microsoft 365 multi-factor authentication, compromising enterprise accounts in under two minutes. The campaign leverages real-time proxy techniques to intercept MFA prompts, allowing attackers to authenticate as legitimate users. Infrastructure defenders must prioritize blocking unauthorized device code flows and implementing conditional access policies that restrict token issuance from suspicious IP ranges. Monitoring for 

___________________________________


# **[Microsoft 365: Block Device Code Flow Against GhostCode](https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973)**

**PIR: 1.d**

Source: ketch Published: 2026-09-16

Microsoft has issued urgent guidance to disable the device code authentication flow following widespread abuse by the GhostCode threat group. Attackers exploit this OAuth mechanism to silently register rogue devices and harvest long-lived access tokens, bypassing traditional MFA controls. IT infrastructure teams should immediately configure Azure AD conditional access rules to block device code grants, audit registered devices for unauthorized enrollments, and enforce certificate-based authentic

___________________________________


# **[Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI](https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing)**

**PIR: 1.h**

Source: ketch Published: 2026-09-16

A sophisticated threat actor linked to Midnight Blizzard is leveraging AI-driven automation to scale device code phishing campaigns against Microsoft 365 environments. The group uses machine learning to dynamically generate convincing login portals and optimize credential harvesting workflows. Infrastructure defenders should deploy AI-aware detection models, monitor for rapid sequential authentication attempts, and restrict device code flows to approved corporate networks. Integrating behavioral

___________________________________


# **[Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA](https://tempmail.ninja/blog/laundry-bear-zimbra-phishing)**

**PIR: 1.f**

Source: ketch Published: 2026-09-16

CISA has alerted organizations to a zero-click phishing campaign exploiting a critical vulnerability in Zimbra Collaboration Suite. The Russian-linked Laundry Bear group leverages this flaw to silently compromise email accounts without user interaction, enabling data exfiltration and lateral movement. Infrastructure teams must immediately patch Zimbra instances, audit email server logs for unauthorized access, and implement network segmentation to isolate mail systems. Deploying endpoint detecti

___________________________________


# **[Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA](https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns)**

**PIR: 1.e**

Source: ketch Published: 2026-09-16

Modern phishing operations increasingly exploit cloud-native services like serverless functions, object storage, and CDN networks to host malicious payloads and evade traditional security controls. Attackers leverage legitimate cloud APIs to dynamically generate phishing domains and distribute credential-harvesting pages at scale. Infrastructure defenders must implement strict cloud security posture management, monitor for anomalous API usage, and enforce egress filtering. Zero-trust network arc

___________________________________


# **[Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining SharePoint](https://threat-intelligence.redeyesecurity.com/blog/passkey-phishing-microsoft-cloud-hijack-storm-3032-2026)**

**PIR: 1.d**

Source: ketch Published: 2026-09-16

Social engineering attacks are increasingly targeting help desk personnel to manipulate passkey registration processes, resulting in unauthorized cloud account takeovers and SharePoint data drainage. Attackers impersonate legitimate users to request passkey resets, bypassing traditional password-based security. IT infrastructure defenders must enforce strict identity verification protocols for support requests, implement multi-person approval workflows for credential changes, and monitor for ano

___________________________________


# **[Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncovers a Massive Canada-First Banking Operation + Video - UNDERCODE NEWS](https://undercodenews.com/fast-flux-phishing-turns-the-internet-into-a-moving-target-as-silent-push-uncovers-a-massive-canada-first-banking-operation-video)**

**PIR: 1.g**

Source: ketch Published: 2026-09-16

Cybercriminals are weaponizing fast-flux DNS networks to create highly resilient phishing infrastructure that rapidly rotates IP addresses and hosting providers. This technique complicates takedown efforts and enables large-scale banking fraud operations targeting Canadian financial institutions. IT defenders should integrate threat intelligence feeds that track fast-flux patterns, deploy DNS-layer filtering, and monitor for rapid domain resolution changes. Implementing email authentication prot

___________________________________


# **[PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs](https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs)**

**PIR: 1.g**

Source: ketch Published: 2026-09-16

The PhantomEnigma threat group has compromised official Brazilian government websites to host phishing pages and malware distribution hubs, leveraging inherent user trust to bypass security awareness training. Attackers exploit outdated web servers and weak access controls to inject malicious scripts that harvest credentials and deploy ransomware. Defenders should conduct regular third-party risk assessments, implement web application firewalls, and monitor for unauthorized content changes on pu

___________________________________


# **[CVE-2026-83059](https://nvd.nist.gov/vuln/detail/CVE-2026-83059)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-15

Vulnerability in the Oracle Internet Directory product of Oracle Fusion Middleware (component: OID LDAP Server).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via LDAP to compromise Oracle Internet Directory.  While the vulnerability is in Oracle Internet Directory, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in

___________________________________


# **[CVE-2026-71133](https://nvd.nist.gov/vuln/detail/CVE-2026-71133)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-15

Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Authentication Engine).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager.  While the vulnerability is in Oracle Access Manager, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeo

___________________________________


# **[CVE-2026-92808](https://nvd.nist.gov/vuln/detail/CVE-2026-92808)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-16

A server-side request forgery (SSRF) vulnerability exists in the UnifiedLogin service of Altium Enterprise Server. An unauthenticated network attacker can cause the server to issue outbound HTTP requests to a destination of the attacker's choosing, including internal services that are reachable only from the server itself.




One such internal service exposes server configuration and credential material without authentication, relying only on the request originating locally. Because the forged 

___________________________________


# **[CVE-2026-20234](https://nvd.nist.gov/vuln/detail/CVE-2026-20234)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-16

As part of Cisco's ongoing commitment to proactive security and product quality, the Cisco Identity Services Engine (ISE) and Cisco ISE Passive Identity Connector (ISE-PIC) engineering teams have conducted a comprehensive internal security review. This review resulted in a software hardening release that addresses multiple internally discovered vulnerabilities.

The vulnerabilities tracked by CVE-2026-20234 are related to insufficiently protected credentials issues that are grouped under the C

___________________________________


# **[CVE-2026-62379](https://nvd.nist.gov/vuln/detail/CVE-2026-62379)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-15

Open Access Management (OpenAM) is an access management solution. Prior to 16.1.2, the pre-authentication /authservice PLL endpoint accepts a CustomCallback XML element whose className value selects an arbitrary Java class for AuthXMLUtils to load and instantiate without verifying that it implements DSAMECallbackInterface. Default configurations expose the endpoint without authentication, allowing attacker-controlled class initialization and unsafe deserialization of a serialized Subject value t

___________________________________


# **[CVE-2026-83066](https://nvd.nist.gov/vuln/detail/CVE-2026-83066)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-15

Vulnerability in the Oracle Internet Directory product of Oracle Fusion Middleware (component: OID LDAP Server).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle Internet Directory.  Successful attacks of this vulnerability can result in takeover of Oracle Internet Directory. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVS

___________________________________


# **[CVE-2026-83062](https://nvd.nist.gov/vuln/detail/CVE-2026-83062)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-09-15

Vulnerability in the Oracle Internet Directory product of Oracle Fusion Middleware (component: OID LDAP Server).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via LDAP to compromise Oracle Internet Directory.  Successful attacks of this vulnerability can result in takeover of Oracle Internet Directory. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Ve

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-18212 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-18212)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Digital Identity sector: unauthenticated DoS in Keycloak's SAML endpoint crashes public-facing IdP instances, disrupting enterprise and government SSO flows.

*Deep dive: `TIER_2_CVE-2026-18212.md`*

___________________________________


# **[CVE-2026-20192 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20192)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Core IdAM platform (Cisco ISE) with actively exploited auth/authz bypasses, directly impacting digital identity and network access controls across government, healthcare, and finance.

*Deep dive: `TIER_2_CVE-2026-20192.md`*

___________________________________


# **[CVE-2026-20194 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20194)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Core enterprise IdAM platform (Cisco ISE) handling authentication, authorization, and credential management, with direct relevance to Digital Identity, Government, Healthcare, and Finance sectors.

*Deep dive: `TIER_2_CVE-2026-20194.md`*

___________________________________


# **[CVE-2026-20237 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20237)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Core Digital Identity infrastructure (Cisco ISE) with unauthenticated RCE/path traversal flaws, directly impacting network access control and credential validation in government, healthcare, and finance.

*Deep dive: `TIER_2_CVE-2026-20237.md`*

___________________________________


# **[CVE-2026-74909 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-74909)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Authorization bypass in Keycloak policy enforcer impacts core Digital Identity infrastructure, allowing authenticated users to access restricted endpoints in public-facing IdP deployments.

*Deep dive: `TIER_2_CVE-2026-74909.md`*

___________________________________


# **[CVE-2026-76423 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76423)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Critical unauthenticated admin bypass in Cisco ISE, a core Digital Identity and AAA platform managing enterprise authentication, authorization, and network access policies.

*Deep dive: `TIER_2_CVE-2026-76423.md`*

___________________________________


# **[CVE-2026-76460 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-76460)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Critical authentication bypass in Cisco ISE, a core enterprise IdAM/AAA platform, enables unauthenticated root access and directly threatens digital identity infrastructure across government, healthcare, and finance sectors.

*Deep dive: `TIER_2_CVE-2026-76460.md`*

___________________________________


# **[CVE-2026-79651 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-79651)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Directly impacts core Digital Identity infrastructure (Keycloak/SSO), causing unauthenticated DoS that blocks all authentication flows for government and enterprise portals.

*Deep dive: `TIER_2_CVE-2026-79651.md`*

___________________________________


# **[CVE-2026-80274 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-80274)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Foundational DNS infrastructure (BIND 9) DoS cascades across Digital Identity, Finance, Healthcare, and Government sectors.

*Deep dive: `TIER_2_CVE-2026-80274.md`*

___________________________________


# **[CVE-2026-81642 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-81642)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Foundational DNS/DNSSEC infrastructure underpinning Government, Finance, and Healthcare digital services; RCE/DoS on resolvers disrupts all dependent public and regulated systems.

*Deep dive: `TIER_2_CVE-2026-81642.md`*

___________________________________


# **[CVE-2026-92794 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-92794)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Compromises unauthenticated access controls and token issuance in a default-deployed e-signature platform, directly impacting Digital Identity verification and Finance/Government contract workflows.

*Deep dive: `TIER_2_CVE-2026-92794.md`*

___________________________________


# **[CVE-2026-19667 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-19667)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Foundational DNS infrastructure (BIND 9) underpins all regulated sectors; unauthenticated remote DoS threatens availability of government, finance, and healthcare digital services.

*Deep dive: `TIER_2_CVE-2026-19667.md`*

___________________________________


# **[CVE-2026-89783 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-89783)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Foundational Linux kernel IPsec vulnerability impacting government, finance, and healthcare infrastructure relying on IPv6 security policies.

*Deep dive: `TIER_2_CVE-2026-89783.md`*

___________________________________


# **[CVE-2026-90049 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-90049)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Foundational Linux kernel networking flaw affecting cloud and NFV infrastructure, posing transitive risk to all hosted DPI services.

*Deep dive: `TIER_2_CVE-2026-90049.md`*

___________________________________


# **[CVE-2026-92804 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-92804)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Manages OAuth flows, credential storage, and API authentication for integrated services, positioning it as critical identity-adjacent infrastructure for regulated and public-sector digital ecosystems.

*Deep dive: `TIER_2_CVE-2026-92804.md`*

___________________________________


# **[CVE-2026-20329 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20329)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Tier 2 critical vulnerability in Cisco Secure Firewall edge appliances, foundational general infrastructure explicitly linked to protecting public and enterprise network perimeters.

*Deep dive: `TIER_2_CVE-2026-20329.md`*

___________________________________


# **[CVE-2026-20330 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20330)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Critical unauthenticated flaw in Cisco Secure Firewall impacts general infrastructure foundational to all regulated and public digital services.

*Deep dive: `TIER_2_CVE-2026-20330.md`*

___________________________________


# **[CVE-2026-20333 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-20333)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

TIER 2 logic flaw in Cisco ASA/FTD edge firewalls, foundational network infrastructure that secures perimeter access for regulated and public digital services.

*Deep dive: `TIER_2_CVE-2026-20333.md`*

___________________________________


# **[CVE-2026-77692 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-77692)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Foundational DNS infrastructure (BIND 9) underpins national digital services; DoS risk to public-facing DoH resolvers used by government/enterprise.

*Deep dive: `TIER_2_CVE-2026-77692.md`*

___________________________________


# **[CVE-2026-82399 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-82399)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Foundational DNS infrastructure vulnerability threatening resolver availability across national digital public infrastructure and regulated sectors.

*Deep dive: `TIER_2_CVE-2026-82399.md`*

___________________________________


# **[CVE-2026-89775 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-89775)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Foundational Linux KVM hypervisor flaw impacting multi-tenant cloud infrastructure underpinning all DPI sectors, though limited to arm64 hosts with nested virtualization enabled.

*Deep dive: `TIER_2_CVE-2026-89775.md`*

___________________________________


# **[CVE-2026-70416 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-70416)**

**PIR: 3.k**

Source: WAVE Published: 2026-09-16

Foundational enterprise object storage that may underpin data lakes and backups for Healthcare, Finance, and Government deployments.

*Deep dive: `TIER_2_CVE-2026-70416.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine