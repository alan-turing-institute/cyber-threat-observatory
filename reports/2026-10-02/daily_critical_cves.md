# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-03 09:38:56Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-10-02`
- **Included count:** 10

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-103602 | Bypasses PKIX certificate validation in a widely used crypto library, directly undermining trust infrastructure for digital identity, finance, and government services. | A trailing dot can break trust: CVE-2026-103602 exposes a PKIX validation flaw in Bouncy Castle C# that bypasses certificate name constraints. Critical for any DPI relying on robust digital identity and secure TLS foundations. |
| 5 | 2 | CVE-2026-104637 | Unauthenticated RCE in a Hospital Management System directly compromises patient data and clinical operations, aligning with Healthcare DPI sector. | Unauthenticated RCE in open-source Hospital Management Systems exposes patient records to immediate compromise. Healthcare providers must patch or harden file uploads to protect clinical data integrity. |
| 4 | 2 | CVE-2026-103600 | Foundational cryptographic library for TLS/PKI underpinning Digital Identity, Finance, and Government services; unauthenticated DoS risks widespread service disruption. | A trivially exploitable DoS in a widely used .NET crypto library could crash internet-facing TLS and PKI services. Patching bc-csharp is critical to protect the availability of digital identity and financial infrastructure. |
| 4 | 2 | CVE-2026-104609 | Unauthenticated SQLi in a hospital management system exposes patient records and credentials, directly impacting the Healthcare sector. | Unauthenticated SQL injection in hospital management software could expose sensitive patient data and credentials. Healthcare IT teams should verify network segmentation and patch legacy PHP/MySQL deployments to prevent data breaches. |
| 4 | 2 | CVE-2026-63568 | Impacts foundational PKI and certificate lifecycle management (CMP/CRMF) in the Digital Identity sector, enabling remote DoS against certificate issuance and verification services. | A remote DoS in a widely used cryptographic library can cripple PKI endpoints, disrupting certificate issuance and digital identity verification. Upgrade bc-csharp or enforce iteration limits to protect your identity infrastructure. |
| 4 | 2 | CVE-2026-63573 | Foundational cryptographic library flaw enabling decryption of secure communications, directly impacting Government, Finance, and Healthcare enterprise email and document exchange. | A padding oracle in a widely used .NET crypto library could silently decrypt secure emails and documents across regulated sectors. Organizations relying on S/MIME or CMS encryption should verify their Bouncy Castle versions and normalize error responses to close the oracle gap. |
| 3 | 2 | CVE-2026-104430 | Impacts decentralized financial infrastructure (Zcash) by enabling unauthenticated consensus divergence and network stalls, disrupting transaction validation and payment availability. | A TIER 2 vulnerability in Zcash’s Zebra node software can silently stall validators off the main chain via crafted transactions, highlighting the fragility of decentralized financial consensus. Organizations relying on crypto infrastructure should prioritize patching to maintain transaction availability and network integrity. |
| 3 | 2 | CVE-2026-104431 | Finance sector relevance: unauthenticated remote DoS disrupts Zcash node availability, impacting cryptocurrency transaction validation and ledger consensus. | A Tier 2 remote DoS in Zcash node software threatens the availability of decentralized financial infrastructure. Operators must patch to Zebra 6.0.0 or restrict P2P access to safeguard transaction validation and network consensus. |
| 3 | 2 | CVE-2026-63574 | Foundational .NET cryptographic library with DoS risk to OpenPGP parsing, impacting digital identity workflows like key management, email signing, and certificate services. | A trivial DoS in a widely adopted .NET crypto library could disrupt OpenPGP-based identity and signing services. Patch bc-csharp to 2.7.0 to safeguard key management and secure communication workflows in regulated environments. |
| 3 | 2 | CVE-2026-63575 | Foundational .NET cryptographic library with broad transitive reach across government, finance, and healthcare stacks; DoS via crafted certificate files threatens availability of regulated services. | A trivial 75-byte payload can exhaust CPU and starve worker threads in any .NET application processing untrusted certificates. Because Bouncy Castle underpins many regulated enterprise and government systems, patching this TIER 2 DoS is critical for maintaining service availability. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-104026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104426.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104434.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104908.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-15999.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16000.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16001.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18036.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63567.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63570.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63571.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63576.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82458.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85476.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86537.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87117.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90970.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94422.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94633.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94635.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94636.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94648.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94653.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-94657.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96286.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96287.md` — heuristic TIER 3/4
