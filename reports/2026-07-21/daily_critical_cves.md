# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-23 20:06:15Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-21`
- **Included count:** 11

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-55084 | SQL injection in DHIS2, a core national health information system deployed by ministries of health and governments, risking patient data and public health operations. | A critical SQL injection flaw in DHIS2 threatens national health data sovereignty. Ministries of health and NGOs must patch immediately to protect patient records and public health analytics from authenticated attackers. |
| 4 | 2 | CVE-2026-47731 | TIER 2 unauthenticated path traversal in NASA-AMMOS AIT-Core ground support software, directly impacting the Government sector's national space infrastructure and internal OT networks. | A critical path traversal in NASA’s AIT-Core ground data system underscores the hidden risks in specialized government OT networks. Even internal-only tools demand strict segmentation and prompt patching to prevent RCE and mission-critical data corruption. |
| 3 | 2 | CVE-2026-28304 | Tier 2 unauthenticated RCE in widely deployed MFT server explicitly tied to handling regulated financial, healthcare, and government data exchanges. | Critical remote code execution in SolarWinds Serv-U (CVE-2026-28304) exposes internet-facing file transfer endpoints to root-level compromise. Organizations in regulated sectors should prioritize patching to protect sensitive data pipelines and prevent unauthorized access. |
| 3 | 2 | CVE-2026-65052 | Finance sector relevance due to unauthenticated payment total manipulation on public-facing WordPress sites, impacting e-commerce, donations, and service bookings. | Public-facing WordPress sites using Ninja Forms for payments are at risk of unauthenticated financial fraud. Patch to v3.14.9+ or disable calculation-based payment forms to prevent attackers from bypassing pricing logic and processing zero-cost transactions. |
| 3 | 2 | CVE-2026-8933 | General infrastructure vulnerability in Ubuntu's snapd affecting public-sector and enterprise deployments that host DPI services. | A ready-to-use PoC for a local privilege escalation in Ubuntu's snapd (CVE-2026-8933) highlights the critical need to patch foundational OS layers underpinning public-sector and enterprise DPI deployments. |
| 3 | 2 | CVE-2026-8982 | Affects publicly deployed EV charging infrastructure (Energy/Transportation) with integrated payment processing, posing operational and financial risks to municipal and commercial networks. | Public EV charging networks face a critical authentication flaw: a hard-coded admin account with a trivially brute-forceable PIN grants full control over payment and telemetry systems. Municipal and commercial operators must patch firmware and segment management traffic immediately to protect critical energy infrastructure. |
| 3 | 2 | CVE-2026-8983 | Hardcoded auth token in internet-exposed EV charging stations threatens public transit infrastructure and integrated payment gateways, aligning with general infrastructure and secondary Finance/Government DPI sectors. | EV charging networks are becoming critical public infrastructure, but hardcoded credentials in devices like the Autel MaxiCharger expose payment gateways and municipal charging hubs to unauthenticated remote control. Patching and network segmentation are essential to protect these expanding civic energy assets. |
| 3 | 2 | CVE-2026-8985 | Unauthenticated RCE in EV charging stations impacts public energy grid resilience and municipal mobility infrastructure. | As EV charging networks become critical public infrastructure, this unauthenticated RCE in Autel chargers underscores the need for strict network segmentation and timely firmware updates to safeguard municipal energy grids. |
| 3 | 2 | CVE-2026-8987 | TIER 2 heap overflow in public EV charging infrastructure firmware enables RCE/DoS, threatening grid load management and public mobility services. | Critical infrastructure alert: A TIER 2 firmware flaw in widely deployed EV chargers allows remote code execution via a hardcoded backdoor token. As public charging networks scale, securing edge IoT devices is essential to prevent grid disruption and service outages. |
| 2 | 2 | CVE-2026-56816 | Foundational Java networking framework (Netty) powering public-facing API gateways and web services; unauthenticated HTTP/3 DoS poses availability risk to regulated digital platforms. | A Tier 2 flaw in Netty’s HTTP/3 codec lets attackers trigger OOM crashes via crafted QUIC streams. Since this framework underpins many public-facing API gateways and citizen services, patching to 4.2.16.Final is a quick win for infrastructure resilience. |
| 2 | 2 | CVE-2026-8984 | Unauthenticated root RCE in publicly deployed EV charging infrastructure impacts national energy and transportation resilience (General Infrastructure), requiring strict network segmentation in municipal/commercial settings. | A TIER 2 critical flaw in Autel EV chargers enables unauthenticated remote code execution, highlighting the need for rigorous network segmentation and firmware hygiene in publicly deployed energy infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-10678.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15226.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15829.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16330.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16359.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16395.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16406.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16408.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16412.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28308.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28312.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28313.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28314.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28316.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-28321.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-3183.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-43946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44878.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47394.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47396.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47397.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47406.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47409.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47414.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47415.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47416.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47419.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47657.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47667.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47685.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47687.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47688.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47697.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55851.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56147.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56745.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59851.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60225.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60495.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60502.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60528.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60703.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-60924.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61062.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61073.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61162.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62466.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62548.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64608.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64609.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64877.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64878.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64880.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65049.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65316.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-6952.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8988.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-8989.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-47050.md` — heuristic TIER 3/4
