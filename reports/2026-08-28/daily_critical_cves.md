# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-29 15:27:08Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-28`
- **Included count:** 14

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-18918 | Critical OAuth authorization bypass in Eclipse Lyo directly undermines trusted client validation and access control in Digital Identity and IdAM systems. | A critical TIER 2 flaw in Eclipse Lyo’s OAuth implementation lets attackers bypass admin approval for trusted clients, exposing a key weakness in enterprise and public-sector identity frameworks. Patching or disabling 2-legged OAuth flows is essential to protect digital identity infrastructure. |
| 5 | 2 | CVE-2026-82262 | SSRF in Logto IdAM platform enables internal network recon and cloud metadata exfiltration via tenant admin APIs, directly impacting digital identity infrastructure. | Open-source identity providers like Logto are foundational to modern digital infrastructure, but management APIs and webhook endpoints can become attack vectors for internal reconnaissance. This TIER 2 SSRF highlights why strict egress controls and token hygiene are non-negotiable for IdAM deployments in regulated sectors. |
| 4 | 2 | CVE-2026-27852 | Foundational enterprise email backend widely deployed across Government, Finance, and Healthcare; targeted IMAP DoS disrupts critical communication continuity. | Enterprise email remains a critical attack surface for DPI. CVE-2026-27852 shows how trivial header manipulation can trigger targeted IMAP DoS in OX Dovecot, disrupting mail access for public sector and regulated enterprise users. Patching is the only mitigation. |
| 4 | 2 | CVE-2026-42007 | Foundational email infrastructure vulnerability enabling RCE and data exfiltration across government, finance, healthcare, and identity systems. | Enterprise mail servers remain a critical attack surface for DPI ecosystems. This TIER 2 RCE in OX Dovecot highlights why securing foundational email infrastructure—and enforcing default-secure configurations—is vital for protecting government, financial, and healthcare data flows. |
| 4 | 2 | CVE-2026-55552 | Unauthenticated path traversal in Yamcs mission control framework impacts government space agencies and national security infrastructure. | National space agencies and defense contractors using Yamcs for mission control face a critical unauthenticated file-read flaw. Patching is essential to protect sensitive telemetry and ground-station infrastructure from data exfiltration. |
| 4 | 2 | CVE-2026-55559 | TIER 2 RCE in Yamcs mission control framework directly impacts the Government sector by compromising critical national space agency telemetry and satellite command infrastructure. | A ready-to-exploit RCE in the Yamcs mission control framework highlights the hidden risks in specialized government space infrastructure. Even internal-only systems require strict authentication and patching to protect national telemetry and command operations. |
| 3 | 2 | CVE-2026-38820 | Unauthenticated RCE in openNDS captive portals impacts municipal public Wi-Fi and government/healthcare guest networks, compromising foundational public access infrastructure. | Municipal and public Wi-Fi networks running openNDS captive portals face unauthenticated remote code execution risks. Patching is critical to protect public access infrastructure and prevent network-wide compromise. |
| 3 | 2 | CVE-2026-38821 | Unauthenticated RCE in openNDS captive portal daemon impacts municipal Wi-Fi and public venue networks, threatening foundational public connectivity infrastructure. | Public Wi-Fi gateways are critical touchpoints for citizen connectivity. This unauthenticated RCE in openNDS highlights the need to harden captive portal infrastructure before attackers turn municipal and airport networks into pivot points. |
| 3 | 2 | CVE-2026-38822 | TIER 2 RCE in openNDS captive portal daemon impacts municipal Wi-Fi and public sector guest networks, posing pivoting and traffic interception risks to civic connectivity infrastructure. | Public Wi-Fi gateways are foundational to civic digital infrastructure. This TIER 2 command injection in openNDS shows how unpatched captive portals can become pivot points for municipal networks—upgrade to v11.0.0 and enforce strict guest-LAN segmentation. |
| 3 | 2 | CVE-2026-42391 | Unauthenticated DoS on foundational enterprise IMAP/email infrastructure that underpins operational communications across public and private sectors. | Enterprise email gateways face a trivial, unauthenticated DoS risk that can crash login processes and disrupt critical organizational communications. Patching or rate-limiting IMAP ports is essential to maintain service availability for public and private sector operations. |
| 3 | 2 | CVE-2026-55848 | Unauthenticated XXE in MapFish Print, a GIS component widely deployed in public-sector mapping and civic spatial services, enables credential theft and SSRF. | Civic GIS portals using MapFish Print are exposed to a weaponized XXE flaw that allows unauthenticated attackers to steal cloud tokens and pivot internally. Agencies should patch or restrict the print API immediately to protect spatial infrastructure. |
| 3 | 2 | CVE-2026-82078 | Actively exploited RCE in enterprise print management software explicitly impacts government and higher education deployments due to potential internet exposure of user portals. | Actively exploited RCE in PaperCut print management systems poses a direct pivot risk to government and university networks. While typically internal, exposed user portals make immediate patching and network segmentation critical for public sector deployments. |
| 3 | 2 | CVE-2026-82244 | Critical RCE in a low-code platform explicitly tied to public-sector and enterprise infrastructure, risking full host compromise and credential theft. | Public-sector and enterprise teams deploying Budibase should patch immediately: a critical RCE allows admin-authenticated attackers to execute arbitrary code with root privileges and exfiltrate JWT secrets. Restricting admin API access and upgrading to v3.41.3+ are essential mitigations. |
| 3 | 2 | CVE-2026-82266 | Critical default-auth bypass in Redpanda data streaming platform, a foundational backend component for regulated sector data pipelines (finance, healthcare, government). | Unauthenticated superuser access in Redpanda’s Admin API by default poses a silent risk to enterprise data pipelines. While typically internal, misconfigured cloud security groups could expose critical streaming infrastructure in regulated sectors—ensure admin auth is enforced. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-13761.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16821.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-17203.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18527.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-37736.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-40541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55068.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55108.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55215.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55485.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55511.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55520.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55565.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55673.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55784.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55841.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56854.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72984.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73208.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75123.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77586.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81020.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81517.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81518.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81520.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81532.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81533.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82021.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82240.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82241.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82242.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82245.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82253.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82261.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82271.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82273.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82278.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82279.md` — heuristic TIER 3/4
