# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-27 12:16:02Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-26`
- **Included count:** 8

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-110475 | Unauthenticated authentication bypass in a BFSI debt collection platform enables full admin takeover and PII/financial data exfiltration, directly impacting national financial infrastructure. | Financial institutions relying on debt collection platforms face critical exposure: an unauthenticated bypass allows attackers to hijack admin sessions and exfiltrate sensitive borrower data without credentials. Patching and enforcing MFA are urgent to protect national financial infrastructure. |
| 5 | 2 | CVE-2026-116587 | Directly impacts Digital Identity infrastructure by enabling remote DoS on JWT/JWK parsing in widely deployed Go-based identity providers and API gateways. | A TIER 2 flaw in the `go-jose` library lets attackers crash public-facing identity providers and API gateways with a single crafted JWT. Organizations relying on token-based authentication should patch immediately to avoid service outages. |
| 4 | 2 | CVE-2026-110474 | Hardcoded API key in a BFSI-focused AI call centre app enables unauthenticated exfiltration of financial customer data and call recordings, directly impacting Finance sector compliance and operations. | A hardcoded API key in a financial services AI call centre app just handed attackers unauthenticated access to sensitive customer call recordings. For BFSI providers, this underscores the critical need for secure secret management and strict API governance in regulated environments. |
| 4 | 2 | CVE-2026-116112 | Unauthenticated SQLi in a public-facing medical appointment system exposes patient records and enables unauthorized doctor account creation. | Healthcare portals handling patient data must enforce strict input validation and session termination. This TIER 2 flaw in an open-source scheduling app shows how a missing exit() can lead to full database exposure. |
| 4 | 2 | CVE-2026-116253 | Unauthenticated remote code injection in DedeCMS, a CMS widely deployed by Chinese government agencies and public institutions for official web portals. | Unpatched public-facing CMS vulnerabilities pose a direct threat to government digital infrastructure. Rapid patching and WAF deployment are critical to protecting civic services from automated exploitation campaigns. |
| 4 | 2 | CVE-2026-116257 | Finance sector relevance: self-hosted billing platform handling payment processor integrations, invoices, and customer financial data, with unauthenticated admin takeover risk during deployment. | Self-hosted billing platforms face a critical setup-phase risk: an unauthenticated install endpoint can grant attackers full admin access to payment data and Stripe integrations. Secure your deployment pipelines and lock down installation routes before going live. |
| 4 | 2 | CVE-2026-116540 | Foundational TLS library for enterprise Java stacks underpins Finance, Government, Healthcare, and Identity services; DoS risk during key rotation impacts regulated public-facing infrastructure. | A race condition in a widely deployed Java TLS library could crash public-facing enterprise services during routine key rotations. Critical for regulated sectors relying on Netty for secure transport. |
| 4 | 2 | CVE-2026-85297 | Foundational GCP deployment tool (Cloud Run MCP) with bucket squatting flaw impacting CI/CD and AI workflows for government, finance, and enterprise cloud infrastructure. | Cloud infrastructure security alert: A bucket squatting flaw in Google Cloud Run MCP could let attackers hijack deployment artifacts and inject malicious code into production workloads. Organizations running government or financial services on GCP should patch to v1.11.0 and enforce randomized storage naming immediately. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-13833.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105608.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105765.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10757.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-110720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112343.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112344.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112346.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112427.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112438.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112484.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112623.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112637.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-112655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113345.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115193.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115693.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115930.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116210.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116218.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116219.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116469.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116489.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116492.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116589.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116612.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116723.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116724.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116738.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-116740.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57187.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59107.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65184.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65327.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65629.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71456.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72753.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72754.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72756.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-72758.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82944.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82947.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86929.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89209.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90885.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94380.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97200.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-116543.md` — heuristic TIER 3/4
