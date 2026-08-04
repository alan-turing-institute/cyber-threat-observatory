# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-08-04 17:47:15Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-08-03`
- **Included count:** 17

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-18089 | Direct SAML authentication bypass in a widely used Perl IdAM library, enabling forged assertions and full access to public-sector and enterprise SSO endpoints. | A default-vulnerable SAML library flaw lets attackers forge identity assertions and bypass authentication entirely. For DPI and enterprise SSO deployments, enforcing trust anchors isn't optional—it's critical. Patch Net::SAML2 to v0.86+ now. |
| 5 | 2 | CVE-2026-18092 | Digital Identity sector: SAML authentication bypass in a core Perl library threatens federated SSO and national digital identity ecosystems. | A critical SAML signature bypass in the Net::SAML2 library enables arbitrary user impersonation across public-facing endpoints. Digital identity teams must prioritize patching to protect federated authentication infrastructure from XML Signature Wrapping attacks. |
| 5 | 2 | CVE-2026-18108 | Critical SAML authentication bypass in a widely used Perl library, directly compromising enterprise and government SSO trust boundaries. | A critical flaw in the Perl Net::SAML2 library allows attackers to forge SAML assertions and bypass authentication entirely. Organizations relying on SAML-based SSO for digital identity must patch immediately to prevent full account takeover. |
| 5 | 2 | CVE-2026-18568 | Directly undermines SAML signature verification in the Digital Identity sector, enabling authentication bypass across enterprise and government SSO/IdAM systems. | A critical signature bypass in a core Perl SAML library could silently grant attackers valid access to enterprise and government SSO gateways. Patching XML::Sig to 0.72 is essential to protect identity federation trust chains. |
| 5 | 2 | CVE-2026-59639 | Directly undermines PKI/CMS signature verification, a foundational control for Digital Identity, Finance, and Government document/transaction authenticity. | A zero-signer bypass in Bouncy Castle’s CMS verification could let unsigned payloads pass as cryptographically valid—threatening the trust anchors for digital identity, government filings, and financial transactions. Patch or add explicit signer-count checks now. |
| 5 | 2 | CVE-2026-9487 | Digital Identity: Critical SAML2 authentication bypass in widely deployed Perl XML signature libraries enables credential forgery and account takeover across public-facing SSO endpoints. | A critical flaw in a core Perl SAML library allows attackers to forge authentication assertions and bypass SSO entirely. Identity teams should prioritize patching XML::Sig to 0.71+ to protect federated access infrastructure. |
| 4 | 2 | CVE-2026-18248 | Critical authentication bypass in a widely used serverless adapter that allows attackers to forge identity claims and bypass access controls, directly impacting Digital Identity infrastructure. | Public-facing serverless APIs built on Fastify/AWS Lambda face a critical identity bypass flaw. Attackers can forge authorizer claims with a single header, bypassing authentication entirely. Patch to v6.4.1 immediately to protect digital identity and access control boundaries. |
| 4 | 2 | CVE-2026-18574 | Critical authentication bypass in Check Point management servers, foundational infrastructure for government and public-sector network security. | Unauthenticated RCE in Check Point Security Management Servers (CVE-2026-18574) threatens the control plane of government and enterprise networks. Patching and strict network segmentation are essential to protect national infrastructure defences. |
| 4 | 2 | CVE-2026-39931 | Healthcare: Authenticated SQLi in widely deployed OpenEMR EHR system risks full patient database compromise and clinical infrastructure disruption. | Healthcare providers running OpenEMR should prioritize admin interface hardening and MFA, as a new authenticated SQL injection (CVE-2026-39931) could allow attackers to extract patient data and manipulate access controls. |
| 4 | 2 | CVE-2026-58062 | Bypasses TLS certificate revocation checking in Bouncy Castle Java, directly undermining PKI foundations critical to Digital Identity and secure government/finance communications. | A TIER 2 flaw in Bouncy Castle Java allows attackers to bypass TLS certificate revocation checks using mismatched OCSP responses. For DPI architects, this highlights the hidden risks in foundational crypto libraries that underpin digital identity and secure citizen services. |
| 4 | 2 | CVE-2026-59646 | Foundational cryptography library (Bouncy Castle) underpins TLS/DTLS for government, healthcare, and finance services; unauthenticated DoS threatens availability of internet-facing digital infrastructure. | A single UDP packet can crash Java services relying on Bouncy Castle for DTLS. As a foundational crypto library powering government, healthcare, and finance platforms, this TIER 2 DoS flaw demands immediate patching to protect critical digital infrastructure availability. |
| 4 | 2 | CVE-2026-67610 | Direct Healthcare sector impact via OpenEMR EHR platform; unauthenticated OAuth2 client registration enables mass PHI disclosure and HIPAA violations in clinical environments. | Healthcare systems using OpenEMR should audit FHIR API configurations and OAuth2 client approval workflows. This TIER 2 flaw shows how interoperability endpoints can become high-impact PHI breach vectors if misconfigured. |
| 4 | 2 | CVE-2026-69078 | SSRF in MISP/CTI-Transmute PDF generator impacts the Government sector, as the tool is core to national CERTs and the ENSOC cross-border cybersecurity coordination platform. | Unauthenticated SSRF in CTI-Transmute’s PDF export function exposes internal SOC networks to reconnaissance and data leakage. Critical patch required for national CERTs and EU cybersecurity agencies relying on the ENSOC platform for threat intelligence coordination. |
| 4 | 2 | CVE-2026-69079 | Unauthenticated DoS in CTI-Transmute disrupts threat intelligence pipelines heavily relied upon by national CSIRTs and government cybersecurity agencies. | A trivial, unauthenticated DoS in CTI-Transmute can cripple threat intelligence sharing pipelines used by national CSIRTs and EU security agencies. Patching this TIER 2 flaw is critical to maintaining the availability of government cyber defense infrastructure. |
| 3 | 2 | CVE-2026-18641 | Unauthenticated RCE in enterprise bastion/IT management platform widely deployed in government and critical infrastructure networks. | Unauthenticated remote code execution in Sangfor's O&M management console poses a direct risk to government and critical infrastructure bastion hosts. Network segmentation and strict access controls are critical until patched. |
| 3 | 2 | CVE-2026-61372 | Path traversal in Apache Jena Fuseki impacts government open-data portals and enterprise knowledge graphs, requiring patching for public-sector data infrastructure. | Government open-data portals and enterprise knowledge graphs running Apache Jena Fuseki face a path traversal risk that could expose sensitive configuration files. Patch to 6.2.0 and restrict SPARQL Update access to secure public-sector data infrastructure. |
| 2 | 2 | CVE-2026-48330 | Tier 2 unauthenticated RCE in enterprise marketing automation; report notes potential government/citizen communications deployment. | Critical unauthenticated SQL injection in Adobe Campaign Classic enables remote code execution on public-facing tracking endpoints. Agencies and enterprises using it for citizen outreach should patch immediately to prevent campaign hijacking and data breaches. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-15628.md` — heuristic TIER 3/4
- `TIER_3_CVE-2025-9291.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-0392.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12852.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12860.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13506.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18605.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18642.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18655.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-18667.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-20483.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21549.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21550.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-21552.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-39932.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48113.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48317.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48326.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48333.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58060.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58061.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59640.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59641.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59642.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59644.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59645.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59649.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59650.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-59651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62870.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65802.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66315.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-66322.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-67611.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68981.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69082.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69095.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69096.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69185.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69244.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69247.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69248.md` — heuristic TIER 3/4
