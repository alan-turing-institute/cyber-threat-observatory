# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-08 09:35:50Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-07`
- **Included count:** 14

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-18355 | Digital Identity sector: core LDAP/IdAM directory server flaw enabling post-auth RCE/DoS, directly impacting enterprise and public-sector authentication infrastructure. | A TIER 2 heap overflow in 389 Directory Server could cripple enterprise and government identity backends. With no workaround available, patching this core IdAM component is critical to protect authentication and SSO pipelines. |
| 5 | 2 | CVE-2026-18453 | Core Digital Identity infrastructure (389/Red Hat Directory Server) with unauthenticated DoS disrupting authentication, SSO, and credential lookups. | Unauthenticated LDAP DoS in 389 Directory Server can crash core identity infrastructure by default, disrupting SSO and enterprise logins. Patch immediately to protect authentication pipelines. |
| 5 | 2 | CVE-2026-18922 | Critical authentication bypass in Red Hat 389 Directory Server enables unauthenticated full Directory Manager privilege escalation, directly compromising core LDAP/IdAM infrastructure (Digital Identity sector). | Unauthenticated attackers can hijack full directory admin rights in Red Hat 389 Directory Server via a stale SASL identity bug. For any organization relying on LDAP/IdAM backends, this TIER 2 flaw demands immediate SASL mechanism hardening and patching to protect your identity store. |
| 5 | 2 | CVE-2026-61410 | Critical unauthenticated RCE in Dell Secure Connect Gateway, a public-facing ZTNA appliance that handles authentication, authorization, and session management for remote digital identity workflows. | Unauthenticated remote code execution in Dell’s Secure Connect Gateway exposes a critical gap in Zero Trust access infrastructure. With no workarounds available, organizations relying on this gateway for secure remote identity and session management must prioritize immediate patching to protect perimeter access controls. |
| 5 | 2 | CVE-2026-76578 | Core Digital Identity infrastructure (FreeIPA/IdM) allowing unauthenticated LDAP clients to forge administrative Kerberos credentials, enabling full identity takeover. | A critical flaw in Red Hat FreeIPA lets attackers bypass authentication to forge admin Kerberos credentials via anonymous LDAP binds. For any organization relying on internal IAM directories, this underscores the urgent need to disable anonymous binds and segment LDAP traffic. |
| 5 | 2 | CVE-2026-80132 | Unauthenticated remote access in Dell's ZTNA/IAM gateway directly compromises digital identity enforcement and public/enterprise network security. | A missing authentication flaw in Dell Secure Connect Gateway (CVE-2026-80132) lets attackers bypass Zero Trust controls without credentials. With no workarounds available, public sector and enterprise IAM deployments must patch immediately to protect remote workforce access. |
| 5 | 2 | CVE-2026-80134 | Hard-coded credentials in a public-facing ZTNA gateway directly compromise authentication and session management for Digital Identity, Government, and Finance deployments. | Unpatched hard-coded credentials in Dell’s Secure Connect Gateway expose public-facing ZTNA deployments to unauthenticated remote access. Organizations relying on this gateway for secure remote identity and access management should prioritize patching to protect critical digital infrastructure. |
| 4 | 2 | CVE-2026-75650 | Critical unauthenticated RCE in widely deployed e-commerce platforms directly impacts the Finance sector by compromising payment processing, customer accounts, and transactional data. | Active in-wild exploitation of a critical Magento/Adobe Commerce vulnerability is enabling unauthenticated RCE on internet-facing storefronts. Finance and retail leaders should immediately disable GraphQL endpoints or patch to protect payment systems and customer data from active backdoor campaigns. |
| 4 | 2 | CVE-2026-82753 | Digital Identity: DoS vulnerability in a foundational OAuth2/OIDC authorization server library that can exhaust database and memory resources on public-facing endpoints. | Identity infrastructure relying on the ash_authentication_oauth2_server Elixir library faces a critical DoS risk when the opt-in CIMD feature is active. Organizations should patch to v0.3.1 or disable CIMD to safeguard public-facing OAuth2 authorization flows. |
| 4 | 2 | CVE-2026-86273 | Unauthenticated SSRF in Brazil's core state government document management system (SIGA), enabling internal reconnaissance and lateral movement in public sector networks. | A default-unauthenticated SSRF in Brazil's widely deployed SIGA government document system exposes internal networks to reconnaissance and lateral movement. Public sector IT teams should enforce endpoint authentication and restrict outbound traffic immediately. |
| 4 | 2 | CVE-2026-86480 | Critical unauthenticated superuser escalation in JetBrains Hub, an internal IdAM platform managing credentials and access for enterprise development tools. | Internal identity providers are prime targets for lateral movement. CVE-2026-86480 allows unauthenticated attackers to register trusted services and seize superuser control of JetBrains Hub, highlighting the need for strict network segmentation and prompt patching of enterprise IdAM stacks. |
| 3 | 2 | CVE-2026-79645 | Unauthenticated remote access to a foundational ZTNA gateway compromises Zero Trust architectures widely deployed for secure remote access in regulated and public-sector environments. | A Tier 2 flaw in Dell’s Secure Connect Gateway allows unauthenticated remote access to internet-exposed Zero Trust gateways. This underscores the critical need to patch foundational security infrastructure that underpins secure remote access for government and enterprise services. |
| 3 | 2 | CVE-2026-80131 | Unauthenticated RCE in internet-facing ZTNA gateway compromises Zero Trust perimeters critical for regulated enterprise and public sector remote access. | Unauthenticated RCE in Dell’s Secure Connect Gateway (CVE-2026-80131) bypasses Zero Trust perimeters by default. With no workarounds available, regulated organizations relying on SCG for secure remote access must prioritize immediate patching to prevent lateral movement and service disruption. |
| 3 | 2 | CVE-2026-84732 | Foundational VPN gateway component for public-sector and enterprise remote access; unauthenticated DoS disrupts critical connectivity pathways. | OpenVPN gateways face unauthenticated DoS risks that can sever remote access for public and enterprise networks. Patching is critical to maintain availability for citizen and workforce connectivity. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-14296.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6223.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6377.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76560.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79697.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79698.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80238.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84173.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84226.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86261.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86347.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86419.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86427.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86439.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86478.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86479.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86482.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86538.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86542.md` — heuristic TIER 3/4
