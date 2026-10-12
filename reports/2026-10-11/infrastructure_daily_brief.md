# **Infrastructure Daily Brief: 2026-10-11**

**Infrastructure Daily Report TLP:GREEN Alert Id: 54f21c09 2026-10-12 04:01:34**

All data contained is **TLP GREEN**. Recipients may share **TLP GREEN** information with peers and partner organizations within the IT infrastructure and digital public infrastructure community, but not via public channels unless reclassified.

## Index

| CATEGORY   | SOURCE                                                                     | PIR(s)   |
|------------|----------------------------------------------------------------------------|----------|
| Cyber News | CVE-2026-108718 (Tier 2)                                                   | 3.k      |
| Threats    | GhostCode attackers abuse device codes to take over Microsoft 365 accounts | 1.b.2    |
| Threats    | Inside an AI‑enabled device code phishing campaign                         | 1.c.1    |
| Threats    | Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass     | 1.b.1    |
| Threats    | Device Code Phishing is an Evolution in Identity Takeover                  | 1.a.3    |
| Threats    | CVE-2026-108865                                                            | 1.b      |

---

## Top Stories


_No top stories selected for this edition._


## Threats


# **[GhostCode attackers abuse device codes to take over Microsoft 365 accounts](https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html)**

**PIR: 1.b.2**

Source: ketch Published: 2026-10-11

Threat actors behind the GhostCode campaign are exploiting Microsoft 365 device code authentication flows to bypass multi-factor authentication and seize enterprise accounts. By tricking users into entering legitimate device codes on malicious portals, attackers gain persistent access to email, Teams, and cloud storage. Infrastructure defenders should monitor for anomalous device code sign-ins, enforce conditional access policies, and educate users on recognizing fake authentication prompts.

___________________________________


# **[Inside an AI‑enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)**

**PIR: 1.c.1**

Source: ketch Published: 2026-10-11

Microsoft security researchers detail a sophisticated phishing operation leveraging generative AI to craft highly convincing device code prompts. The campaign dynamically adapts language and branding to match target organizations, significantly increasing click-through rates. Defenders are advised to deploy AI-aware email filtering, restrict device code usage to trusted networks, and implement continuous authentication monitoring to detect rapid credential validation attempts.

___________________________________


# **[Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass](https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html)**

**PIR: 1.b.1**

Source: ketch Published: 2026-10-11

Trend Micro analyzes how the convenience of device code authentication is being weaponized to circumvent traditional MFA controls. Attackers host fake login pages that prompt users to input codes generated on their primary devices, effectively transferring session tokens to malicious infrastructure. IT teams should evaluate the risk-benefit ratio of device code flows, enforce step-up authentication for sensitive actions, and deploy endpoint detection to block unauthorized browser-based auth redi

___________________________________


# **[Device Code Phishing is an Evolution in Identity Takeover](https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover)**

**PIR: 1.a.3**

Source: ketch Published: 2026-10-11

Proofpoint examines the tactical shift from traditional credential harvesting to device code exploitation as a primary identity takeover vector. This evolution allows threat actors to bypass passwordless and MFA protections by leveraging legitimate OAuth flows. Security operations centers must update detection rules to flag rapid device code validations, implement zero-trust access controls, and conduct regular identity hygiene audits to mitigate lateral movement risks.

___________________________________


# **[CVE-2026-108865](https://nvd.nist.gov/vuln/detail/CVE-2026-108865)**

**PIR: 1.b**

Source: vulners/duckdb Published: 2026-10-11

AmoyLab Unla through 0.10.0 contains an authentication bypass vulnerability that allows unauthenticated attackers to obtain valid access tokens because the OAuth2 server never authenticates a resource owner. Attackers can register a client, request a code from /authorize, and exchange it at /token to access OAuth2-protected MCP prefixes, proxied upstream APIs and injected credentials.

___________________________________



## Policy and standards



## Infrastructure operations



## Cyber news


# **[CVE-2026-108718 (Tier 2)](https://nvd.nist.gov/vuln/detail/CVE-2026-108718)**

**PIR: 3.k**

Source: WAVE Published: 2026-10-11

Digital Identity sector: directly compromises OAuth authorization flows and token issuance, enabling persistent account takeover in data/analytics platforms.

*Deep dive: `TIER_2_CVE-2026-108718.md`*

___________________________________



---

**Value feedback:** Submit items for the next edition via your CyberObs watch desk contact.

--- NOTIFICATION ---

This report is derived from open-source and API-sourced information. No warranty is provided. The recipient is solely responsible for decisions based on this material.

**TLP GREEN** | Review Precedence: Routine