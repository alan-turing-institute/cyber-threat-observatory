# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-13 12:36:43Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-12`
- **Included count:** 18

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 4 | 2 | CVE-2026-111552 | Authentication bypass in internet-facing e-commerce infrastructure directly threatens payment processing and transactional integrity, aligning with the Finance sector. | E-commerce platforms handling payments and transactions are prime targets for authentication bypasses. This TIER 2 flaw in Hyper Teknoloji's infrastructure highlights the critical need for robust access controls in finance-facing digital services. |
| 4 | 2 | CVE-2026-116335 | Foundational PostgreSQL database engine with OS-level RCE risk, directly impacting Finance, Healthcare, and Government data storage and transaction systems. | PostgreSQL powers critical backend systems across finance, healthcare, and government. This TIER 2 type confusion flaw enables OS-level code execution for privileged DB users—patching and privilege hardening are essential to protect public data infrastructure. |
| 4 | 2 | CVE-2026-120868 | Foundational edge infrastructure (Citrix NetScaler) heavily deployed across Government, Finance, and Healthcare; unauthenticated DoS directly threatens availability of regulated digital public services. | Citrix NetScaler ADC/Gateway faces a critical, unauthenticated memory overflow (CVE-2026-120868) that can crash edge appliances by default. With widespread deployment across government, finance, and healthcare networks, this TIER 2 vulnerability demands immediate patching to protect critical digital public services from widespread outages. |
| 4 | 2 | CVE-2026-124005 | Impacts healthcare pharmaceutical cold-chain and critical supply infrastructure via unauthenticated remote compromise of internet-exposed supervisory controllers. | A TIER 2 flaw in internet-exposed refrigeration controllers reveals how deterministic passwords can jeopardize pharmaceutical cold-chain integrity. With the product already EoS, network segmentation and strict access controls are the only defenses for healthcare and logistics operators. |
| 4 | 2 | CVE-2026-127046 | Unauthenticated API key disclosure in MISP Modules, a foundational threat intelligence platform widely deployed by government and critical infrastructure operators. | MISP is a cornerstone of government and critical infrastructure threat sharing. This TIER 2 flaw exposes external enrichment API keys without authentication, risking credential theft and quota abuse in internal threat intel workflows. Patch or enforce admin passwords immediately. |
| 4 | 2 | CVE-2026-127111 | Unauthenticated account takeover in widely deployed public-sector and enterprise webmail infrastructure, enabling lateral movement and data exfiltration. | Public-facing groupware servers like SOGo are prime targets for automated account takeover via unrate-limited password recovery. Organizations relying on open-source collaboration platforms for citizen or employee services must enforce MFA and WAF rate-limiting immediately. |
| 4 | 2 | CVE-2026-127121 | Foundational groupware deployed across Government and Healthcare IT enables S/MIME certificate spoofing, compromising encrypted communications in regulated environments. | SOGo groupware, a staple in Government and Healthcare email infrastructure, contains a TIER 2 flaw allowing attackers to spoof S/MIME certificates via crafted emails. Patching is critical to protect encrypted communications in regulated public services. |
| 4 | 2 | CVE-2026-127131 | Directly impacts Digital Identity by bypassing TOTP 2FA in SOGo groupware, enabling full account takeover for public-facing enterprise and government collaboration portals. | SOGo groupware deployments face a critical 2FA bypass flaw that lets attackers brute-force TOTP codes once a password is known. For public sector and enterprise identity teams, this underscores the need for network-level rate limiting alongside patching to protect collaboration portals. |
| 4 | 2 | CVE-2026-127204 | Finance sector: unauthenticated payment bypass in WooCommerce PayPal Pro enables fraudulent order fulfillment and direct merchant revenue loss. | A critical unauthenticated flaw in the WooCommerce PayPal Pro plugin allows attackers to mark unpaid orders as paid, triggering fraudulent fulfillment and direct financial loss. Merchants should patch immediately to secure payment processing workflows. |
| 4 | 2 | CVE-2026-19422 | Foundational DNS/DHCP/IPAM management infrastructure underpinning Healthcare, Finance, and Government digital services; internal auth bypass enables network-wide traffic redirection and service disruption. | Unauthenticated DNS/DHCP manipulation in enterprise network management tools can silently redirect traffic or disrupt critical public and financial services. Patching internal infrastructure is just as vital as securing public-facing endpoints. |
| 3 | 2 | CVE-2026-111433 | Container runtime flaw in openEuler iSulad enables host data exfiltration, directly impacting government and telecom infrastructure deployments. | A TIER 2 container escape vulnerability in openEuler’s iSulad runtime could expose sensitive host data across government and telecom networks. While exploitation requires prior image deployment access, it underscores the critical need for strict registry governance and pre-deployment scanning in public-sector cloud environments. |
| 3 | 2 | CVE-2026-114556 | General infrastructure email server widely deployed in regulated sectors (government, finance, healthcare); unauthenticated RCE risk threatens core communications. | Unauthenticated directory traversal in MailEnable (CVE-2026-114556) poses a systemic risk to regulated sectors relying on on-premises email. Patching to v10.60 is critical to prevent arbitrary file creation and potential RCE in government, finance, and healthcare environments. |
| 3 | 2 | CVE-2026-120150 | Foundational backend database for regulated/public services; TIER 2 RCE mandates prompt patching across enterprise and government deployments. | PostgreSQL administrators should prioritize patching CVE-2026-120150, a TIER 2 use-after-free vulnerability enabling OS-level RCE. As a core backend engine for critical public and regulated services, timely updates are essential to maintain infrastructure resilience. |
| 3 | 2 | CVE-2026-13672 | General infrastructure NAS platform widely deployed across government and enterprise environments, with an SSOAuth authorization bypass impacting data storage and access controls. | Synology NAS devices are staples in government and enterprise data infrastructure. This TIER 2 authorization bypass in the SSOAuth module highlights the critical need for credential hygiene and timely patching in internet-facing storage deployments. |
| 3 | 2 | CVE-2026-18596 | MFA bypass on widely deployed enterprise and government NAS infrastructure enables arbitrary file access and full system compromise. | Foundational storage systems in government and enterprise environments are facing a critical MFA bypass flaw. Patching Synology DSM is essential to protect sensitive data repositories and maintain trust in digital infrastructure. |
| 3 | 2 | CVE-2026-47259 | Impacts building automation controllers widely deployed in hospitals and government facilities, posing operational risk to critical infrastructure. | Unauthenticated RCE in the open-source BACnet stack threatens building automation systems in hospitals and government facilities. Patching and strict OT/IT segmentation are critical to protect critical infrastructure. |
| 2 | 2 | CVE-2026-47711 | BACnet stack vulnerability impacts building automation systems that underpin healthcare and government facilities, posing DoS risks to critical facility management. | A Tier 2 stack overflow in the open-source BACnet library could crash building automation controllers on internal networks. While not internet-facing, this underscores the need for strict segmentation and patching in healthcare and government facility management systems. |
| 2 | 2 | CVE-2026-85101 | TIER 2 authentication bypass in Synology DSM rsync service; impacts foundational NAS infrastructure widely deployed in government and enterprise backup environments. | Synology DSM administrators should prioritize patching CVE-2026-85101, a TIER 2 rsync authentication bypass enabling unauthenticated file writes. Though disabled by default, government and enterprise NAS deployments must verify service exposure and apply vendor fixes to protect backup infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2024-21954.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106475.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107443.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110951.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111435.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116316.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116319.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116328.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116329.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116331.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116835.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118597.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120139.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120143.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120144.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120145.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120147.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120148.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120149.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120153.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-120869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124002.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124013.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124015.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124691.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124696.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124697.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124698.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12507.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12591.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126191.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127016.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127030.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127141.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-127208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14661.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18379.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18447.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18633.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19421.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47832.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6460.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75867.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75869.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8331.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8332.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86322.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-127029.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-13269.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-13270.md` — heuristic TIER 3/4
