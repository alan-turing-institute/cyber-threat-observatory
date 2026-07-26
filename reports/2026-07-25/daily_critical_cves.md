# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-07-26 08:26:03Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-07-25`
- **Included count:** 2

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 3 | 2 | CVE-2026-66013 | General infrastructure IoT platform explicitly tied to smart city and municipal deployments, risking notification hijacking and operational disruption in public-sector IoT management. | Smart city and municipal IoT platforms face a critical authentication bypass in OpenRemote, allowing attackers to hijack console notifications and disrupt public infrastructure monitoring. Patching is essential for cities relying on open-source IoT management for civic services. |
| 3 | 2 | CVE-2026-66374 | General infrastructure DNS resolver widely deployed in public sector and ISP networks; RCE in encrypted DNS path impacts core network reliability. | DNS resolvers form the backbone of public and enterprise networks. This TIER 2 RCE in Knot Resolver’s DoQ implementation underscores the need to audit encrypted DNS deployments and patch foundational infrastructure, even when advanced features are disabled by default. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-66373.md` — heuristic TIER 3/4
