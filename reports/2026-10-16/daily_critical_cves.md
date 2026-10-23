# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-10-22 13:43:18Z
- **Reports folder:** `/root/cyberobs-backfill-20261021/reports/2026-10-16`
- **Included count:** 14

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-105279 | Critical missing authentication in hospital DICOM imaging archives allows unauthenticated exfiltration and injection of patient medical records, directly impacting healthcare data integrity and confidentiality. | Healthcare infrastructure alert: A critical flaw in widely deployed DICOM archives allows attackers on internal networks to steal or fabricate patient imaging data without credentials. Hospitals must enforce AE registration and patch immediately to protect clinical workflows and PHI. |
| 5 | 2 | CVE-2026-97851 | Directly impacts Healthcare DPI by enabling unauthenticated deletion of DICOM medical images in hospital PACS systems, threatening patient safety and clinical continuity. | Unauthenticated deletion of medical imaging archives in hospital PACS systems highlights the critical need for network segmentation and patching in healthcare infrastructure. Protecting patient data integrity is paramount for resilient digital public health services. |
| 4 | 2 | CVE-2026-111607 | Finance sector: IDOR in open-source payment gateway enables cross-tenant payment redirection and configuration hijacking, directly impacting financial operations and merchant accounts. | Payment gateways handling public transactions must enforce strict tenant isolation. This IDOR in Jeepay demonstrates how missing ownership checks can allow authenticated users to hijack payment routing and signing keys, posing a direct threat to financial infrastructure integrity. |
| 4 | 2 | CVE-2026-111636 | Critical authentication bypass in an enterprise digital-employee platform enables unauthenticated admin takeover via forged session tokens, directly impacting Digital Identity and access management controls. | Enterprise platforms defaulting to hard-coded signing secrets for session tokens create trivial admin takeover risks. This TIER 2 flaw in OpenBMB StaffDeck underscores why zero-trust identity controls and credential rotation must be baked into deployment defaults, not left to manual fixes. |
| 4 | 2 | CVE-2026-111641 | Critical auth bypass in FastapiAdmin framework compromises JWT session management and RBAC, directly impacting Digital Identity and internal access control systems. | A trivially exploitable authentication bypass in FastapiAdmin allows attackers to forge superuser JWT sessions and bypass RBAC controls. For DPI and regulated environments relying on internal admin frameworks for identity management, this underscores the critical need for strict network segmentation and WAF rules until patched. |
| 4 | 2 | CVE-2026-111690 | Critical authentication bypass in an enterprise IdAM backend framework via a hard-coded JWT secret, directly impacting Digital Identity and access management infrastructure. | A hard-coded JWT secret in an enterprise admin framework allows trivial super-admin impersonation. For digital identity teams, this highlights the urgent need to audit default cryptographic keys in IdAM and RBAC backends. |
| 4 | 2 | CVE-2026-111691 | Finance sector relevance: Critical authentication bypass in a multi-tenant ERP platform enables unauthorized access to financial records, order processing, and transactional data. | A TIER 2 flaw in WIMOOR ERP shows how trusting internal headers without cryptographic verification can break multi-tenant financial isolation. For regulated e-commerce and finance deployments, this highlights the critical need for strict gateway enforcement and header validation. |
| 4 | 2 | CVE-2026-111697 | Finance sector relevance due to direct manipulation of digital wallets, recharge transactions, and payment integrity in a public-facing EV charging platform. | Broken access control in a public EV charging platform allows authenticated users to drain or inflate digital wallets and harvest PII. Highlights the critical need for server-side authorization checks in fintech-adjacent IoT and mobility services. |
| 4 | 2 | CVE-2026-111719 | Finance sector: missing authorization in open-source payment gateway exposes sensitive merchant transaction records and financial data. | Payment gateways handling merchant transactions must enforce strict API authorization. This TIER 2 flaw in an open-source gateway allows unauthenticated access to financial records via predictable transaction IDs, highlighting critical risks in fintech infrastructure. |
| 4 | 2 | CVE-2026-86008 | Mail servers underpin cross-sector digital operations by handling 2FA delivery, password resets, and official communications for government, finance, and healthcare environments. | Compromised mail admin panels can bypass 2FA and hijack official communications across government and regulated sectors. Patching privilege escalation flaws in foundational email infrastructure is critical for maintaining national digital resilience. |
| 3 | 2 | CVE-2026-111633 | Hard-coded JWT signing key enables unauthenticated admin impersonation, directly compromising digital identity and authentication mechanisms in public-facing CMS deployments. | A hard-coded JWT secret in a web CMS allows attackers to forge admin tokens with zero interaction. For DPI and regulated web services, this underscores the critical need to rotate cryptographic keys and avoid compile-time constants in authentication flows. |
| 3 | 2 | CVE-2026-111680 | Cross-tenant authorization bypass in an open-source API gateway impacts multi-tenant government and financial service deployments relying on centralized API management. | API gateways are the backbone of modern digital public services, but a single misconfigured middleware can break tenant isolation. CVE-2026-111680 shows how authenticated team managers in APIPark can bypass controls and access other teams' services—highlighting the need for strict network segmentation and MFA in regulated API deployments. |
| 3 | 2 | CVE-2026-111698 | Finance sector relevance due to unauthorized wallet balance manipulation and payment bypass in an EV charging platform backend. | A TIER 2 IDOR flaw in an EV charging platform backend allows authenticated users to manipulate wallet balances and bypass payments. Highlights the critical need for strict session-bound authorization in fintech and infrastructure-adjacent SaaS deployments. |
| 3 | 2 | CVE-2026-68906 | Unauthenticated DoS in IEC 61850 library threatens national energy grid and industrial automation stability, warranting critical infrastructure monitoring. | TIER 2 alert: A trivially exploitable DoS in the open-source IEC 61850 library could disrupt power grids and manufacturing automation. Critical infrastructure operators should patch to v1.6.2 and enforce strict network segmentation. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-101021.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-101300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102551.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102552.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102917.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-102941.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-104715.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105227.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105228.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105667.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105958.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-105959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107621.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-107777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-108374.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109119.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109587.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-109588.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111373.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111375.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111377.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111378.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111379.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111381.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111382.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111383.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111384.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111387.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111447.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111472.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111605.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111614.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111615.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111622.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111634.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111651.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111669.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111671.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111681.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111682.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111684.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111695.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111696.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111700.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-111701.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-16453.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44977.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48503.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48741.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49410.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49868.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63618.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64610.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-64959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68572.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-68907.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69076.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-69080.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85746.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-85748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86009.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86047.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-92262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96627.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97380.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-105273.md` — heuristic TIER 3/4
