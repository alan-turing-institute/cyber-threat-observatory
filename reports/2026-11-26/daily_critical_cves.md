# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-27 12:02:57Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-26`
- **Included count:** 30

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2017-20291 | High-severity XXE in Broadcom SiteMinder SSO federation services directly compromises enterprise authentication and identity assertion boundaries. | Unauthenticated XXE in a core enterprise SSO platform highlights the persistent risks in legacy federation endpoints. Patching or disabling exposed SOAP routers is critical to protect digital identity infrastructure. |
| 5 | 2 | CVE-2026-124843 | Hard-coded crypto fallback in SEPPmail SEG enables unauthenticated token forgery and account takeover, directly impacting Digital Identity, Government, and Finance secure communications. | A hard-coded cryptographic fallback in SEPPmail Secure Email Gateway allows attackers to forge authentication tokens and decrypt confidential transfers without credentials. With widespread adoption in Swiss government and financial sectors, this TIER 2 flaw underscores the critical need to audit legacy crypto dependencies in public-facing identity and email infrastructure. |
| 5 | 2 | CVE-2026-130637 | Pre-auth SSTI in internet-facing secure email gateway widely deployed in Swiss government and healthcare sectors, enabling unauthenticated account takeover. | A critical pre-authentication flaw in SEPPMAIL's secure email gateway exposes Swiss government and healthcare communications to unauthenticated account takeover. Organizations relying on this infrastructure for official and clinical correspondence should prioritize patching to v15.1.2 immediately. |
| 5 | 2 | CVE-2026-137579 | Directly compromises JWT/JWE cryptographic foundations used in modern authentication and session management, impacting Digital Identity infrastructure across regulated and public services. | A timing side-channel in widely used PHP JWT libraries could allow attackers to recover RSA private keys and forge authentication tokens. While remote exploitation faces network jitter hurdles, the risk to digital identity infrastructure makes patching and algorithm migration critical for public and enterprise services. |
| 5 | 2 | CVE-2026-137581 | Directly impacts Digital Identity infrastructure by enabling DoS against JWT validation services foundational to OAuth/OIDC/SSO ecosystems used in government and enterprise access portals. | A TIER 2 DoS in a widely used PHP JWT library could knock out public-facing identity providers and enterprise SSO gateways. Enforce strict token size limits at the web server layer immediately while patching to keep authentication services available. |
| 5 | 2 | CVE-2026-137582 | Directly impacts JWT/OAuth/OIDC processing in public-facing authentication services, threatening availability of core Digital Identity infrastructure. | A DoS flaw in a widely used PHP JWT library could cripple public-facing login and SSO endpoints. For Digital Identity architects, this underscores the need to harden token validation pipelines and restrict niche cryptographic serializers on internet-exposed auth services. |
| 4 | 2 | CVE-2026-124840 | TIER 2 session confusion in SEPPmail SEG enables account takeover via security questions, directly impacting Digital Identity and secure email infrastructure in public sector and regulated industries. | SEPPmail's internet-facing webmail component allows attackers to hijack recovery sessions and take over accounts using just a security question answer. Critical for organizations relying on secure email gateways for government and regulated sector communications. |
| 4 | 2 | CVE-2026-124842 | Impacts Digital Identity by allowing unauthenticated forced password resets and API token revocation in enterprise email gateways, disrupting credential integrity and access controls. | Enterprise email gateways are critical to identity workflows. This TIER 2 flaw lets attackers force password resets and revoke API tokens without authentication, highlighting the need to secure legacy recovery endpoints in regulated environments. |
| 4 | 2 | CVE-2026-134705 | TIER 2 privilege escalation in a widely deployed WordPress OTP/MFA plugin directly compromises authentication workflows and credential verification, impacting the Digital Identity sector. | A TIER 2 flaw in a popular WordPress OTP/MFA plugin lets low-privilege users escalate to full admin access, bypassing multi-factor authentication controls. Organizations relying on this plugin for citizen or employee login flows should patch immediately to protect their identity infrastructure. |
| 4 | 2 | CVE-2026-137500 | Privilege escalation in a low-code platform widely adopted by government and healthcare for citizen portals and internal workflows, risking full tenant takeover. | Low-code platforms are accelerating digital service delivery, but a single invite-code flaw in Budibase could hand attackers full admin control over government and healthcare citizen portals. Patch to 4.0.0 now to protect your public-facing workflows. |
| 4 | 2 | CVE-2026-137523 | Default-vulnerable Google SSO bypass in ToolJet, an internal platform widely deployed across government, healthcare, and finance for administrative workflows and dashboards. | Internal tool builders like ToolJet are increasingly central to government and healthcare operations, but a default-vulnerable Google SSO bypass could grant attackers full account takeover. Organizations should patch or enforce OAuth audience validation immediately to prevent lateral movement in critical admin dashboards. |
| 4 | 2 | CVE-2026-137536 | Critical OAuth SSO authentication bypass in a low-code platform, directly impacting Digital Identity workflows and internal application security. | SSO integration isn't a set-and-forget feature. This critical ToolJet flaw demonstrates how skipping email_verified and sub claim validation can hand attackers full admin access via crafted OAuth tokens. |
| 4 | 2 | CVE-2026-137550 | TIER 2 authorization bypass in Frappe Framework compromises data integrity and enables privilege escalation in ERP/CRM systems widely deployed across Finance and Government digital infrastructure. | A critical authorization flaw in the Frappe Framework (CVE-2026-137550) allows authenticated users to bypass document permissions, posing a direct threat to data integrity in government and financial ERP/CRM deployments. Patching is essential for regulated environments relying on open-source business stacks. |
| 4 | 2 | CVE-2026-137552 | Directly impacts Digital Identity and general infrastructure by bypassing 2FA and session controls in the widely deployed Frappe web framework via an OAuth2 password grant flaw. | Public-facing ERP and citizen services built on Frappe face a critical authentication gap: stolen credentials can now bypass 2FA and forced resets via an undocumented OAuth2 grant. Patching is essential to protect identity and session management in regulated deployments. |
| 4 | 2 | CVE-2026-137559 | Impacts Digital Identity infrastructure by enabling CPU exhaustion DoS on JWT-based authentication and session management endpoints. | A TIER 2 flaw in a widely used PHP JWT framework can cripple public-facing authentication endpoints via crafted tokens. Ensure GMP is enabled or patch immediately to protect your digital identity and session management stacks. |
| 4 | 2 | CVE-2026-137560 | Impacts core Digital Identity infrastructure by enabling unauthenticated DoS against JWT/DPoP verification in OAuth/OIDC providers and public-facing authentication endpoints. | Unauthenticated attackers can exhaust CPU on public identity providers by sending oversized JWTs, highlighting the need for strict token size limits and patched JWT libraries in critical authentication stacks. |
| 4 | 2 | CVE-2026-137564 | Directly impacts the Digital Identity sector by compromising JWT token integrity and authentication mechanisms in public-facing web applications and APIs. | A cryptographic weakness in a foundational PHP JWT library could enable token forgery and session hijacking in digital identity architectures. While exploitation requires a specific misconfiguration, it highlights the critical importance of strict key management and validation in authentication systems. |
| 4 | 2 | CVE-2026-137580 | Impacts Digital Identity infrastructure by enabling DoS against JWT-based authentication and session management endpoints via CPU exhaustion. | A TIER 2 DoS in a widely used PHP JWT library could knock out public-facing identity verification endpoints. Enforce request size limits and patch to keep citizen and enterprise auth gateways resilient. |
| 4 | 2 | CVE-2026-137583 | Directly impacts financial payment orchestration infrastructure by allowing unauthenticated webhook forgery to manipulate transaction states, posing a high fraud risk to merchant operations. | Payment orchestration platforms are the backbone of modern digital commerce, but a hardcoded webhook secret in Juspay Hyperswitch could let attackers forge successful payment events. Merchants relying on this infrastructure should verify their webhook configurations and patch immediately to protect transaction integrity. |
| 4 | 2 | CVE-2026-52803 | Session fixation in self-hosted Git platform undermines authentication and access control, directly impacting Digital Identity assurance and sensitive codebases in government/finance sectors. | Self-hosted developer platforms are critical to the software supply chain, but session fixation flaws like CVE-2026-52803 can bypass authentication and compromise sensitive government or financial codebases. Ensuring strict session rotation and cookie hardening remains essential for protecting digital identity and infrastructure integrity. |
| 3 | 2 | CVE-2026-123910 | General infrastructure: unauthenticated hypervisor RCE in VMware ESXi, foundational to government, finance, and healthcare datacenters. | Hypervisor security is foundational to digital public infrastructure. This Tier 2 flaw in VMware ESXi allows unauthenticated remote code execution on internal management networks, highlighting the need for strict network segmentation and patching in government and regulated datacenters. |
| 3 | 2 | CVE-2026-123911 | Critical unauthenticated RCE in VMware ESXi hypervisor, a foundational compute layer underpinning government, finance, and healthcare digital infrastructure. | A critical, unauthenticated RCE in VMware ESXi (CVE-2026-123911) highlights the persistent risk to foundational virtualization layers. While deployed internally by default, the lack of authentication on the I/O filter service demands immediate firewall hardening and patching across regulated enterprise environments. |
| 3 | 2 | CVE-2026-124844 | Tier 2 unauthenticated DoS in a foundational email gateway that underpins government and regulated sector communications. | Unauthenticated disk exhaustion in SEPPmail SEG (CVE-2026-124844) can halt webmail and mail queues for public and enterprise users. Patch to 15.1.2 or enforce upload rate-limiting to keep critical email gateways online. |
| 3 | 2 | CVE-2026-137389 | Enterprise email gateway RCE impacting government and financial sector communications infrastructure; requires authentication but poses high operational risk to regulated mail flows. | Authenticated RCE in widely deployed enterprise email gateways highlights the need for strict access controls and rapid patching in government and financial mail infrastructure. Public exploit code lowers the barrier for targeting regulated communications. |
| 3 | 2 | CVE-2026-137390 | Enterprise email archiving platform widely deployed across government, finance, and healthcare for compliance; authenticated RCE enables full server compromise and data exfiltration. | CVE-2026-137390 introduces an authenticated OS command injection in Openfind Mail2000, a critical email archiving platform for regulated sectors. Organizations in government, finance, and healthcare should patch immediately to prevent full server compromise and compliance data breaches. |
| 3 | 2 | CVE-2026-137481 | Critical authorization bypass in a widely deployed edge reverse proxy that underpins public-facing digital services across government, finance, and healthcare sectors. | A critical auth bypass in Traefik reverse proxy could let attackers slip past edge security controls into protected APIs and admin panels. Organizations running cloud-native or public-facing services should patch immediately to prevent unauthorized access. |
| 3 | 2 | CVE-2026-137551 | General-purpose framework (Frappe/ERPNext) underpins Government and Finance deployments; RCE via Jinja sandbox bypass impacts regulated web platforms. | Frappe/ERPNext instances in government and finance sectors face a Tier 2 RCE risk via a Jinja sandbox bypass. While exploitation requires high-privilege template authoring access, the flaw highlights the critical need for strict permission controls and timely patching in regulated enterprise environments. |
| 2 | 2 | CVE-2026-135205 | General infrastructure web framework flaw impacting public-facing APIs; report explicitly advises DPI organizations to prioritize patching. | A Tier 2 authentication bypass in the Fastify Node.js framework could allow unauthenticated access to protected API routes. DPI teams deploying Fastify for public services should upgrade to 9.3.10+ or enforce preHandler hooks immediately. |
| 2 | 2 | CVE-2026-137457 | General infrastructure remote access tooling deployed in government and enterprise environments; unauthenticated input injection enables lateral movement on internal management networks. | Internal IT support tools like FreeRDP often fly under the radar, but this unauthenticated keystroke injection flaw shows why government and enterprise networks must strictly segment and patch remote access infrastructure. |
| 2 | 2 | CVE-2026-137478 | TIER 2 authentication bypass in Traefik edge proxy impacts public-facing service gateways commonly used in regulated/cloud-native DPI deployments. | Edge security alert: A TIER 2 auth bypass in Traefik’s ForwardAuth middleware allows credential reuse via Proxy-Authorization headers. Organizations running public-facing digital services should verify middleware configs and patch to v2.11.62+/v3.7.18+. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-109921.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123685.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123905.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123906.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-123907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127041.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127162.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127163.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135384.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135385.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136760.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136976.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137415.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137458.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137459.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137496.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137519.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137525.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137526.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137531.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137534.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137537.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137538.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137543.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137545.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137546.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137549.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137556.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137566.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66784.md` — heuristic TIER 3/4
