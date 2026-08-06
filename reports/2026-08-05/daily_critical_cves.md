# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-06 15:16:11Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-05`
- **Included count:** 17

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-15572 | Core IdAM platform (Keycloak) vulnerability allowing privilege escalation to realm admin via DCR policy bypass, directly impacting digital identity and access management infrastructure. | A logic flaw in Keycloak's Dynamic Client Registration allows attackers to bypass mapper restrictions and escalate to full realm administrator. Critical for organizations relying on Keycloak for OAuth/OIDC identity services to patch immediately. |
| 5 | 2 | CVE-2026-15573 | Keycloak authorization bypass impacts core IdAM/SSO controls, directly affecting Digital Identity infrastructure for government, healthcare, and finance sectors. | Keycloak users face a high-severity authorization bypass allowing URI manipulation to evade security policies. Critical for IdAM teams managing SSO and API access in regulated sectors to patch immediately. |
| 5 | 2 | CVE-2026-16102 | TIER 2 authorization bypass in Keycloak's Dynamic Client Registration enables standard users to forge admin roles, directly impacting Digital Identity infrastructure and enterprise IdP deployments. | Keycloak administrators: A new TIER 2 flaw in Dynamic Client Registration could let compromised standard accounts escalate to full realm admin. Patch your IdP endpoints and restrict DCR access to trusted networks immediately. |
| 5 | 2 | CVE-2026-16442 | Directly impacts core Digital Identity infrastructure by enabling authentication bypass and account takeover in Keycloak's SAML federation workflows. | A new TIER 2 vulnerability in Keycloak (CVE-2026-16442) allows attackers to bypass SAML link-only restrictions and hijack user sessions via IdP-initiated SSO. Organizations relying on Keycloak for enterprise or government identity federation should prioritize patching to prevent targeted account takeover. |
| 5 | 2 | CVE-2026-16443 | Directly impacts the Digital Identity sector by bypassing SAML signature validation in Keycloak, enabling account takeover in federated authentication flows. | A signature validation bypass in Red Hat Keycloak’s SAML broker could allow attackers to forge authentication tokens and take over federated user accounts. Organizations relying on Keycloak for digital identity services should audit IdP configurations and apply patches immediately. |
| 4 | 2 | CVE-2026-18854 | Unauthenticated SQLi in PDM software widely deployed across China's defense industrial base and state-linked manufacturing, posing government sector and supply chain risks. | Internal engineering tools are often overlooked in threat models, but this unauthenticated SQLi in a widely deployed PDM system highlights how industrial software vulnerabilities can directly impact defense supply chains and state-linked manufacturing. Securing the digital backbone of critical infrastructure starts with hardening internal enterprise platforms. |
| 4 | 2 | CVE-2026-18969 | TIER 2 unauthenticated RCE in a government command and dispatch platform used by public security and emergency management agencies. | Critical command-and-control systems face unauthenticated RCE risks. This TIER 2 flaw in a widely deployed government dispatch platform highlights the need for strict network segmentation and WAF rules for public-sector operational tech. |
| 4 | 2 | CVE-2026-18970 | Unauthenticated SQLi in a government command and dispatch platform used for public security and emergency response. | Public security and emergency response systems face heightened risk from unauthenticated SQL injection flaws. With a published exploit available, government agencies deploying command and dispatch platforms must prioritize patching and network segmentation to protect critical civic coordination data. |
| 4 | 2 | CVE-2026-20263 | Foundational Cisco IOS XE networking software underpins government and regulated sector infrastructure, making remote DoS a high-availability risk for public digital services. | Cisco IOS XE devices form the backbone of government and regulated sector networks. This TIER 2 remote DoS vulnerability highlights the need to audit legacy management protocols like BEEP and enforce strict network segmentation to protect critical public infrastructure availability. |
| 4 | 2 | CVE-2026-20272 | Critical injection flaws in Cisco IOS XE network OS (CVSS 9.8) threaten foundational connectivity for government, finance, healthcare, and digital identity infrastructure. | Cisco IOS XE routers and switches face critical injection vulnerabilities (CVSS 9.8) with no workarounds. As foundational infrastructure for regulated sectors, immediate patching is essential to protect public and enterprise network integrity. |
| 4 | 2 | CVE-2026-20301 | Foundational Cisco routing/switching infrastructure underpins government and national digital services; DoS risk to core network nodes warrants attention despite disabled-by-default feature. | Cisco IOS/IOS XE routers form the backbone of government and critical national infrastructure. While the XMCP DoS flaw requires explicit configuration, patching or ACL hardening remains essential to protect foundational network availability. |
| 4 | 2 | CVE-2026-20310 | Critical internal management plane flaw in foundational SD-WAN infrastructure supporting FedRAMP/government and enterprise deployments; requires patching due to zero workarounds. | Internal network management isn't just a perimeter issue—CVE-2026-20310 highlights a critical, unpatched flaw in Cisco SD-WAN controllers that could enable lateral movement and config theft. With no workarounds available, regulated and government deployments must prioritize upgrades to protect foundational routing infrastructure. |
| 4 | 2 | CVE-2026-44945 | General infrastructure Kubernetes orchestrator explicitly tied to Government and Finance deployments; privilege escalation grants full control plane and secrets access across regulated environments. | A default user role in Rancher can be weaponized to hijack entire Kubernetes control planes, exposing secrets and downstream clusters. Critical for Government and Finance teams relying on centralized K8s management to patch and restrict cluster import permissions immediately. |
| 4 | 2 | CVE-2026-55707 | TIER 2 cross-tenant authorization bypass in OpenStack Neutron, a foundational cloud networking stack explicitly noted for government and enterprise deployments. | Multi-tenant cloud isolation is a critical trust boundary for public digital services. This TIER 2 flaw in OpenStack Neutron demonstrates how a single API misconfiguration can compromise tenant routing and NAT, reinforcing the need for strict RBAC and timely patching in government and enterprise cloud environments. |
| 3 | 2 | CVE-2026-18859 | Unauthenticated SQLi in a government/enterprise DLP platform, risking internal data breaches in regulated networks. | A public PoC exists for an unauthenticated SQL injection in ESAFENET CDG, a DLP system widely used in government and enterprise settings. Verify internal exposure and deploy WAF rules to safeguard sensitive document repositories. |
| 3 | 2 | CVE-2026-20268 | Foundational enterprise networking stack (Cisco IOS XE) underpins government, healthcare, and financial infrastructure, requiring prompt patching due to high severity and lack of workarounds. | High-severity memory corruption in Cisco IOS XE (CVSS 8.6) demands immediate attention for public sector and regulated networks. With no workarounds available, DPI operators should prioritize patching edge and core routers to safeguard critical service continuity. |
| 3 | 2 | CVE-2026-20270 | Foundational networking OS for edge routers and firewalls that underpins connectivity for regulated and public digital services. | CVE-2026-20270 highlights the critical need to patch foundational network infrastructure. With no workarounds available, unpatched Cisco IOS XE edge devices pose a severe availability risk to the connectivity backbone of digital public services. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-10025.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17617.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17625.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18485.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18897.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18900.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18902.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18953.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20124.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20200.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20312.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25703.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54876.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55522.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55523.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55739.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55997.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66298.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67592.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70426.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70601.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70604.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70608.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71190.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71206.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71214.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71226.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71259.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71268.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71284.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71289.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71312.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7327.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7329.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7557.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8400.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8470.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9081.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9190.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9192.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9193.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9205.md` — heuristic TIER 3/4
