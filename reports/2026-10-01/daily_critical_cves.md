# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-02 10:29:08Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-01`
- **Included count:** 5

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-76143 | TIER 2 MFA bypass in Genian SSL PNS/ZTNA gateways directly compromises public-facing authentication and identity verification infrastructure. | A TIER 2 flaw in Genian SSL PNS allows attackers to bypass MFA on public-facing NAC and ZTNA gateways via simple parameter manipulation. Critical for organizations relying on these identity gateways for secure remote access. |
| 4 | 2 | CVE-2026-103264 | Authentication bypass in Fleet MDM exposes device management APIs in Government, Finance, and Healthcare sectors, risking unauthorized device control and data access. | Fleet MDM users in regulated sectors face a critical authentication bypass allowing unauthenticated access to device APIs via predictable identifiers. Patching to 4.87.0 is essential to protect Government, Finance, and Healthcare device fleets from unauthorized control and data exposure. |
| 4 | 2 | CVE-2026-73975 | Impacts national and institutional research data repositories (Government/Public Research Infrastructure), threatening metadata integrity and public data trust in critical scientific infrastructure. | A new TIER 2 vulnerability in djehuty, the backend for national research data repositories, allows authenticated users to corrupt shared RDF metadata via SPARQL injection. With trivial account acquisition via ORCID/SAML, public-sector scientific infrastructure faces direct integrity risks until patched to v26.3.2. |
| 4 | 2 | CVE-2026-76142 | Critical zero-trust policy server flaw undermines government and critical infrastructure access controls, though external exploitation requires explicit proxy misconfiguration. | Zero-trust isn't just a concept—it's a policy server. This TIER 2 flaw in Genian NAC/ZTNA shows how a single misconfigured proxy can bypass foundational access controls in government and critical infrastructure networks. Patch and audit your exposure. |
| 4 | 2 | CVE-2026-76146 | TIER 2 RCE in Genian SSL PNS VPN/ZTNA gateway, a foundational perimeter access control explicitly tied to government and critical infrastructure deployments. | A remote code execution flaw in a widely deployed enterprise VPN/ZTNA gateway could provide attackers with a trusted foothold into government and critical infrastructure networks. Organizations should prioritize patching and enforce network-level restrictions on authentication endpoints. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-101322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103249.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103251.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103252.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103254.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103255.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103259.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103488.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103490.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-103921.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12405.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12541.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12544.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13043.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46729.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56589.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64946.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64948.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64949.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66246.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67105.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-75786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-76145.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79896.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79898.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79899.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79901.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80275.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-80276.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82824.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82828.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-88789.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96577.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96658.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96659.md` — heuristic TIER 3/4
