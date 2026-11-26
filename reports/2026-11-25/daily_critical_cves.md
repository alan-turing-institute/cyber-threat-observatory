# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-26 13:43:01Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-25`
- **Included count:** 10

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-136706 | Critical unauthenticated SQLi in the eGov Foundation DIGIT platform directly compromises Government citizen services and Digital Identity/access management functions. | Municipal and state agencies running the DIGIT platform must patch immediately: an unauthenticated SQL injection in core identity services exposes citizen data and disrupts public digital infrastructure. |
| 5 | 2 | CVE-2026-82489 | Unauthenticated RCE in openIMIS directly compromises national health insurance and government healthcare data infrastructure. | Critical unauthenticated RCE in openIMIS exposes national health insurance platforms to full host compromise. Governments and healthcare providers must patch immediately to protect patient records and benefit payment systems. |
| 5 | 2 | CVE-2026-82491 | Impacts national health insurance platforms (Healthcare/Government) by enabling JWT key extraction and silent admin session forgery, undermining core identity and access controls. | National health insurance systems running openIMIS face silent admin takeover risks via JWT key extraction. Patching is critical to protect citizen health data and government identity controls. |
| 4 | 2 | CVE-2026-123879 | Core Ubuntu authentication daemon vulnerability enabling UID/GID hijacking and account takeover, directly impacting Digital Identity and enterprise IdP integrations. | A race condition in Canonical’s authd daemon could let attackers hijack UIDs during SSH logins, bypassing access controls on Ubuntu servers. Critical for teams relying on cloud identity providers and enterprise SSH authentication to patch before account boundaries blur. |
| 3 | 2 | CVE-2026-134642 | General infrastructure risk: widely deployed Linux administration tool used in enterprise and government IT, with unauthenticated root RCE impacting backend server management. | Unauthenticated root RCE in Webmin's cluster feature underscores the risks of internet-exposed administration panels in government and enterprise infrastructure. Patching and strict network segmentation are essential to secure backend management stacks. |
| 3 | 2 | CVE-2026-134792 | General web framework vulnerability impacting public sector and civic tech stacks by enabling MITM attacks on backend API calls and credential interception. | Symfony's HttpClient proxy hijack (CVE-2026-134792) poses a Tier 2 risk to public-facing civic and government web services, enabling attackers to intercept API tokens and credentials via crafted headers. Patch or explicitly configure proxy settings to secure outbound API traffic. |
| 3 | 2 | CVE-2026-135142 | General web infrastructure flaw in the Laravel-MongoDB stack that risks mass data corruption across user collections in public-facing identity, finance, and government portals. | A TIER 2 authorization flaw in the Laravel-MongoDB driver could let low-privilege users wipe entire user collections. Public services and regulated apps relying on this stack should patch immediately to protect citizen and customer data integrity. |
| 3 | 2 | CVE-2026-135226 | TIER 2 data integrity flaw in MongoDB Ruby driver impacts Finance, Government, and Healthcare systems that parse untrusted Extended JSON, risking transaction and record manipulation. | A TIER 2 type-confusion flaw in the MongoDB Ruby driver could let attackers silently alter stored data in financial, government, and healthcare apps. Patching is critical for any regulated service processing untrusted Extended JSON. |
| 3 | 2 | CVE-2026-136632 | Widely adopted in public-sector project management; allows authenticated or anonymous users to delete projects and expose restricted data. | OpenProject, a staple in government and enterprise project management, faces a TIER 2 vulnerability allowing project deletion and data exposure. Patching is critical for public-sector deployments relying on it for civic initiatives. |
| 3 | 2 | CVE-2026-137077 | Foundational remote desktop library (FreeRDP) widely deployed in enterprise and government environments for secure remote access; heap corruption enables RCE/DoS. | FreeRDP's H.264 encoder flaw (CVE-2026-137077) allows remote code execution via crafted RDP sessions. As a foundational remote access stack for government and enterprise, patching to v3.33.0 is critical to protect remote work infrastructure. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2024-7430.md` — heuristic TIER 3/4
- `TIER_3_CVE-2024-7431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105609.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124606.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130336.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-131827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133973.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133974.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133975.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133978.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133979.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134070.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134283.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134323.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134438.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134440.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134444.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134463.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134630.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134635.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134638.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134646.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134647.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135134.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135135.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135146.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135400.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135404.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135888.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-135898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136500.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136501.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136502.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136503.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136505.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136507.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136512.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136515.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136862.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136863.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136881.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136910.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136914.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136916.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-136920.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137085.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137087.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137088.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137089.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-137090.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62154.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64845.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66052.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-73517.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77230.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78114.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82495.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95533.md` — heuristic TIER 3/4
