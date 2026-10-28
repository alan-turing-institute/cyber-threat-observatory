# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-28 12:28:06Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-27`
- **Included count:** 7

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-116672 | Directly compromises OAuth/OIDC authorization servers, enabling token interception and client takeover in core Digital Identity infrastructure. | A critical authorization bypass in Authlib (CVE-2026-116672) allows attackers to hijack OAuth/OIDC client registrations and intercept tokens. Organizations relying on this library for public-facing identity providers should patch immediately to protect authentication flows. |
| 4 | 2 | CVE-2026-104189 | Authorization bypass in Nextcloud 3D Viewer exposes password-protected shared files, impacting secure document exchange in Government, Healthcare, and Finance sectors. | Nextcloud deployments in public and regulated sectors face a critical authorization bypass in the 3D Viewer app, allowing attackers to download password-protected shared files with just a token. Patch to v3.3.2 or disable the app to protect sensitive collaboration workflows. |
| 4 | 2 | CVE-2026-111107 | Unauthenticated management-plane DoS in widely deployed enterprise firewalls, directly impacting government, healthcare, and financial network perimeters and administrative control. | Firewalls are the backbone of digital public infrastructure, but an unauthenticated DoS in WatchGuard Fireware OS could lock administrators out of critical government and healthcare network perimeters. Patching and restricting management access remain essential to keep citizen-facing services resilient. |
| 4 | 2 | CVE-2026-112352 | Critical authentication bypass in Sunhillo SureLine surveillance gateways deployed across FAA, defense, and utility networks, posing severe risks to Government and national security infrastructure. | Unauthenticated root RCE in critical surveillance gateways used by the FAA and defense sectors highlights the persistent risks of weak session management in government-critical infrastructure. Patching and strict network segmentation are essential to protect national security data. |
| 4 | 2 | CVE-2026-112353 | Actively exploited stored XSS in enterprise webmail enables direct credential and session theft, directly impacting Digital Identity and regulated sector communications. | Active in-the-wild exploitation of KerioConnect Webmail is turning routine email previews into credential-stealing traps. For DPI and regulated sectors, this underscores why MFA and strict attachment handling remain critical defenses against session hijacking. |
| 4 | 2 | CVE-2026-77167 | Persistent unauthenticated DoS on Nextcloud Server, a widely deployed digital sovereignty platform critical for government and healthcare collaboration and data availability. | Nextcloud instances powering government and healthcare services face a persistent DoS risk via the federated sharing endpoint. While requiring specific configuration, the self-renewing nature of this flaw underscores the need for strict app management and timely patching in public-sector deployments. |
| 3 | 2 | CVE-2026-57190 | SQL injection in Asterisk PBX logging backends impacts Government and enterprise telecommunications infrastructure. | Asterisk PBX systems, widely deployed in government and enterprise communications, contain a SQL injection flaw in optional logging modules. Organizations should patch or disable unused backends to safeguard critical telecom infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-101034.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103593.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103594.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104350.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104351.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105477.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105779.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105781.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-106174.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108014.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108015.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108142.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108304.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108305.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108306.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108329.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111582.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111584.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111585.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112350.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112351.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112709.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112710.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114596.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114597.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-114598.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115216.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115413.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116620.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116656.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116676.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116843.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-117341.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-117466.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-117493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-117494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-118008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-24269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57186.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57188.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57195.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57197.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57200.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57201.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57202.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65151.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65211.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65220.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76933.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76934.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76935.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76936.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76937.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76938.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82118.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82120.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82121.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82122.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85299.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86574.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86575.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87086.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88812.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90464.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90465.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92376.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92377.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93434.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93864.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94347.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-116649.md` — heuristic TIER 3/4
