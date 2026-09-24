# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-24 02:17:17Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-22`
- **Included count:** 22

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-17635 | Finance sector: Critical auth bypass in IBM Financial Transaction Manager threatens banking operations and payment integrity. | IBM's Financial Transaction Manager has a critical flaw allowing unauthenticated bypass of transaction controls. Banks and financial institutions running FTM on OpenShift must patch immediately to prevent unauthorized payment manipulation. |
| 5 | 2 | CVE-2026-18074 | Core financial transaction infrastructure (IBM FTM) with unauthenticated remote access, directly impacting payment processing and transaction integrity for banks and clearinghouses. | Unauthenticated remote access to IBM's Financial Transaction Manager could allow attackers to manipulate core payment pipelines and transaction rules. Financial institutions running FTM on OpenShift must patch immediately to protect critical financial infrastructure. |
| 5 | 2 | CVE-2026-18163 | Critical RCE in IBM Financial Transaction Manager directly impacts the Finance sector by threatening banking payment routing and core transaction processing infrastructure. | A critical deserialization flaw in IBM’s Financial Transaction Manager could allow attackers to manipulate payment routing and exfiltrate credentials within banking networks. With no workarounds available, financial institutions running OpenShift-based transaction backends must prioritize patching to safeguard core payment infrastructure. |
| 5 | 2 | CVE-2026-75791 | Unauthenticated REST API bypass in a widely deployed enterprise IAM/password self-service platform directly compromises identity lifecycle management and SSO integrations. | CVE-2026-75791 exposes a critical authentication bypass in ManageEngine ADSelfService Plus, allowing unauthenticated attackers to tamper with admin configurations and disrupt enterprise identity workflows. Organizations relying on this platform for password self-service and SSO should prioritize patching to build 7001 to protect their identity infrastructure. |
| 5 | 2 | CVE-2026-94127 | Critical unauthenticated RCE in F5 BIG-IP APM identity gateways actively exploited in the wild, directly threatening enterprise and government SSO/OAuth federation trust anchors. | Active exploitation of F5 BIG-IP APM (CVE-2026-94127) is now on the CISA KEV catalog, targeting the OAuth/SSO gateways that power modern digital identity ecosystems. Organizations relying on perimeter identity brokers must verify configurations and apply hotfixes immediately to protect critical access flows. |
| 4 | 2 | CVE-2026-58268 | Unauthenticated remote DoS in a foundational VoIP/SIP library disrupts emergency dispatch and hospital communications, impacting Government and Healthcare DPI sectors. | A ready-to-exploit DoS in a widely used Go SIP library could knock out emergency dispatch and hospital VoIP systems. Patching sipgo to v1.4.1 is critical for any public-facing telecom or healthcare communication stack. |
| 4 | 2 | CVE-2026-80148 | Unauthenticated SSRF in out-of-band management hardware widely deployed in government, defense, and telecom infrastructure enables internal network pivoting and reconnaissance. | Unauthenticated SSRF in Lantronix out-of-band management devices poses a silent pivot risk for government and telecom networks. Even internal-only deployments require immediate patching or strict segmentation to protect critical infrastructure control planes. |
| 4 | 2 | CVE-2026-80149 | Unauthenticated SSRF in Lantronix out-of-band management appliances widely deployed in government and critical infrastructure networks, enabling internal reconnaissance and lateral movement. | Out-of-band management is a critical backbone for government and telecom infrastructure, but an unauthenticated SSRF in Lantronix devices could turn these trusted appliances into pivot points for attackers. Patching and strict network segmentation are essential to protect internal management VLANs. |
| 4 | 2 | CVE-2026-80155 | Government: unauthenticated RCE in out-of-band management infrastructure deployed across DoD and public safety networks. | Critical unauthenticated bypass in Lantronix out-of-band management gear (CVE-2026-80155) threatens DoD and public safety networks. While deployed internally by default, the detailed exploit mechanics and lack of patches for legacy models demand immediate segmentation and firmware updates. |
| 4 | 2 | CVE-2026-87121 | Critical RCE in the widely deployed lwIP MQTT stack directly impacts IoT/ICS devices across healthcare, finance, and government/critical infrastructure sectors. | A critical RCE in the lwIP MQTT stack (CVE-2026-87121) exposes embedded IoT and ICS devices across healthcare, finance, and public utilities. Patching and network segmentation are essential to protect critical digital infrastructure from remote compromise. |
| 4 | 2 | CVE-2026-88419 | RCE in a CMS widely deployed for Chinese government and public-sector websites, directly impacting civic digital infrastructure (Government sector). | A high-severity RCE in WuzhiCMS (CVE-2026-88419) threatens government and public-sector websites relying on this platform. Agencies should prioritize patching or enforce strict upload controls to safeguard civic digital services. |
| 4 | 2 | CVE-2026-89420 | Finance sector: Payment bypass in HTTP 402 machine-to-machine commerce middleware directly compromises transaction integrity and revenue assurance for public-facing financial APIs. | A TIER 2 payment bypass in machine-to-machine commerce middleware allows attackers to replay signed vouchers and drain paid API resources without further charge. For finance and regulated API operators, this underscores the critical need for robust transaction state validation and independent usage tracking in payment gateways. |
| 4 | 2 | CVE-2026-93556 | Unauthenticated account takeover in a municipal management platform directly impacts Government/civic infrastructure operations and citizen data. | Municipal governments relying on cloud facility management platforms face critical exposure: a trivial password reset flaw allows attackers to seize admin control without authentication. Patching and MFA are essential to protect civic services. |
| 4 | 2 | CVE-2026-93616 | Actively exploited pre-auth RCE in Check Point management servers, foundational security infrastructure widely deployed across Government and Finance sectors. | Actively exploited and CISA KEV-listed, this pre-auth RCE in Check Point management servers threatens the security backbone of government and financial networks. Immediate patching and strict network segmentation are critical to protect national digital infrastructure. |
| 4 | 2 | CVE-2026-94450 | Foundational QUIC transport library vulnerability impacting public-facing edge services, carrying systemic availability risk across all regulated DPI sectors. | A single crafted UDP packet can take down public-facing QUIC servers using AWS s2n-quic, highlighting the systemic risk of vulnerabilities in foundational transport layers that underpin modern digital public services. Patch to v1.89.0 or disable Retry packets immediately. |
| 4 | 2 | CVE-2026-94456 | Compromises OAuth tokens, PKCE verifiers, and API keys via predictable PRNG, directly impacting Digital Identity and organizational SaaS authentication workflows. | A critical flaw in Postiz exposes how weak PRNG can break OAuth and PKCE protections, granting attackers SUPERADMIN access. For DPI and enterprise SaaS, this underscores the non-negotiable need for cryptographically secure credential generation and hardened DCR endpoints. |
| 4 | 2 | CVE-2026-94491 | Unauthenticated SQLi in Yonyou KSOA ERP/OA suite, widely deployed in Chinese government administrations, state-owned enterprises, and financial institutions. | Unauthenticated SQL injection in Yonyou KSOA poses a direct risk to Chinese government and financial back-office systems. Network segmentation and immediate patching are critical to prevent lateral movement and data breaches in regulated environments. |
| 4 | 2 | CVE-2026-94493 | Critical missing authentication in retail POS terminals exposes plaintext admin credentials, directly threatening payment processing integrity and cash handling operations in the Finance sector. | Unauthenticated access to POS management interfaces can leak admin credentials and compromise payment integrity. Retail and finance operators must enforce strict network segmentation and monitor WebSocket traffic to protect core transaction infrastructure. |
| 4 | 2 | CVE-2026-95814 | Authorization bypass in a self-hosted credential vault impacts Digital Identity by allowing revoked or pending members to retain full access to organizational secrets. | Self-hosted password managers are critical to enterprise secret management, but a missing status check in Vaultwarden lets revoked users retain full vault access. Organizations relying on open-source credential stores should patch immediately and audit stale membership records. |
| 3 | 2 | CVE-2026-34689 | Unauthenticated path traversal in widely deployed enterprise conferencing platform used across government, healthcare, and education sectors. | Internet-exposed conferencing platforms like Adobe Connect are prime targets for unauthenticated file-read attacks. Public sector and healthcare deployments should prioritize patching to v12.12 to prevent credential harvesting and data exposure. |
| 3 | 2 | CVE-2026-65634 | Foundational Erlang/OTP runtime DoS impacts TLS handshakes across telecom, finance, and government microservices, threatening public-facing service availability. | A single crafted TLS handshake can freeze Erlang/OTP services for over 10 seconds per core. With OTP powering critical telecom, finance, and government backends, this unauthenticated DoS demands immediate patching before it becomes a mass-outage vector. |
| 2 | 2 | CVE-2026-81995 | General infrastructure (AEM Forms) widely deployed in public-sector and regulated enterprise environments for digital service delivery. | Adobe AEM Forms RCE (CVE-2026-81995) requires high privileges but remains a priority patch for government and enterprise form-processing platforms. Ensure strict admin access controls and apply the Priority 2 update. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-13087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16468.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16672.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17102.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17618.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17636.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17644.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18066.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18123.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18131.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18137.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18162.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18172.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18457.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18462.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19480.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24239.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24267.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-25255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47116.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61570.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63104.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65128.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65130.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68956.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-70410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-74849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75689.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75698.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75743.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75744.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76711.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76713.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76714.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77243.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77251.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77256.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77257.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77258.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77259.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77261.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77426.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77544.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77555.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77556.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77912.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7866.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80152.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80156.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82003.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82010.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82011.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82443.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83597.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83598.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-83803.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-84388.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85055.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87081.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90882.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91018.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93345.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94384.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95619.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95654.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95861.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95862.md` — heuristic TIER 3/4
