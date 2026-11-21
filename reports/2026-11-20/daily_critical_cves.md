# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-21 22:49:26Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-20`
- **Included count:** 14

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-129175 | Critical unauthenticated SQL injection in a U.S. Department of the Interior web portal, directly impacting federal land management and government digital infrastructure. | A critical, unauthenticated SQL injection flaw in a U.S. Department of the Interior application could grant attackers full database and root access to federal land management systems. With public exploit code available, government agencies must prioritize immediate patching and WAF deployment to protect sensitive environmental and operational data. |
| 5 | 2 | CVE-2026-133705 | TIER 2 SAML open redirect in Hanko IdP enables full account takeover via token exfiltration, directly impacting Digital Identity and enterprise SSO infrastructure. | A TIER 2 flaw in Hanko's SAML flow lets attackers bypass redirect allowlists and steal session tokens, turning phishing clicks into full account takeovers. Identity providers relying on wildcard configs should patch to v3.2.0+ immediately to protect public-facing SSO gateways. |
| 5 | 2 | CVE-2026-55216 | Core open-source IdAM platform vulnerability enabling full account takeover via unverified OAuth/Azure AD social connectors, directly impacting digital identity verification and session integrity. | A TIER 2 flaw in Logto exposes how unverified email claims in OAuth/Azure AD connectors can lead to full account takeover. For DPI and regulated services relying on open-source identity infrastructure, this underscores the critical need to enforce email verification and audit social sign-in configurations. |
| 5 | 2 | CVE-2026-77326 | Impacts Government and General Infrastructure by exposing internet-facing public GIS/WMS endpoints (land registries, emergency routing, census data) to unauthenticated DoS and potential RCE. | Public-sector GIS platforms like MapServer are routinely exposed to citizens for land registries and emergency routing. This unauthenticated heap overflow in WMS endpoints poses a direct DoS and RCE risk to government spatial data infrastructure, demanding immediate patching. |
| 4 | 2 | CVE-2026-129073 | Directly impacts Digital Identity infrastructure by bypassing OTP/2FA controls on public-facing WordPress deployments, enabling unauthorized account takeover. | Active exploitation of a widely used WordPress 2FA plugin is bypassing OTP controls and granting unauthorized admin access. Public sector and enterprise sites relying on miniOrange for identity verification should deploy WAF mitigations and patch immediately to protect citizen and user accounts. |
| 4 | 2 | CVE-2026-129177 | Unauthenticated account creation in a U.S. Department of the Interior application directly impacts Government sector digital infrastructure and data integrity. | A TIER 2 vulnerability in a U.S. federal agency's management system highlights the risks of unauthenticated endpoints in government digital infrastructure. Patching and network segmentation remain critical for public-sector resilience. |
| 4 | 2 | CVE-2026-131163 | Finance sector relevance: stored XSS in a payment plugin enables API redirection and session takeover, risking interception of financial transaction data. | Payment integrations are critical touchpoints in digital public infrastructure. This stored XSS in a ticketing platform's payment plugin shows how misconfigured API endpoints can lead to session takeover and financial data exposure, underscoring the need for strict configuration controls in regulated payment flows. |
| 4 | 2 | CVE-2026-133872 | Impacts self-hosted credential stores and JWT authentication endpoints, enabling brute-force account takeover in Digital Identity infrastructure. | Self-hosted password managers and identity backends are exposed to unlimited credential stuffing due to missing default rate limiting on JWT login endpoints. Organizations relying on LessPass for enterprise or government credential management should patch immediately or deploy WAF throttling to secure authentication flows. |
| 4 | 2 | CVE-2026-133949 | Foundational Python package manager vulnerability enabling supply chain compromise via MitM, impacting CI/CD and server-side deployments across all regulated sectors. | Compromised certificates in pip could let attackers inject malicious packages into Python environments via MitM. Upgrade to 26.2.2 or patch Python immediately to secure your software supply chain. |
| 4 | 2 | CVE-2026-133968 | Healthcare sector relevance: medical imaging AI platform deployed on clinical/research networks, risking patient data privacy and workflow disruption via unauthenticated RCE. | AI-driven medical imaging tools are accelerating healthcare innovation, but default configurations can leave clinical networks exposed. CVE-2026-133968 highlights the critical need for authentication and network isolation in healthcare AI deployments. |
| 4 | 2 | CVE-2026-14914 | Unauthenticated RCE in enterprise contact center software widely deployed by government, finance, and healthcare sectors for public-facing service operations. | Public service call centers and banking support platforms running Tegsoft Contact Center face critical unauthenticated RCE risk. With a public exploit available, government and healthcare operators must patch immediately or restrict external upload endpoints to protect citizen and patient data. |
| 4 | 2 | CVE-2026-77309 | Unauthenticated RCE in NASA's AIT-GUI mission operations framework directly impacts government space and aerospace critical infrastructure. | An unauthenticated RCE in NASA's AIT-GUI mission control console underscores the risks facing internal aerospace infrastructure. Even with network segmentation, trivial exploitation paths demand immediate patching to safeguard government space operations. |
| 4 | 2 | CVE-2026-77324 | Unauthenticated DoS in MapServer, a foundational open-source GIS platform widely deployed by government agencies for national Spatial Data Infrastructures and public mapping portals. | Public-facing government mapping portals and civic SDI deployments face immediate risk from a trivial, unauthenticated DoS in MapServer. With ready-to-use PoCs and no runtime mitigations, agencies must patch or restrict WCS endpoints to prevent service exhaustion. |
| 3 | 2 | CVE-2026-127027 | Unauthenticated RCE in a widely deployed self-hosted mail server impacts foundational email infrastructure used by enterprises and government agencies. | Email remains a critical pillar of digital public infrastructure. This unauthenticated RCE in Poste.io highlights the risks of default-facing mail services and underscores the need for proactive patching and edge filtering in government and enterprise environments. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-101340.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-113347.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-115407.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124767.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124768.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124770.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-124772.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-126054.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129074.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129176.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129178.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129179.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129971.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-129972.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-130494.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132658.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132661.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132663.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-132664.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133199.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133534.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133626.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133631.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133648.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133652.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133659.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133660.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133662.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133663.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133835.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133837.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133839.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133847.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133854.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133874.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-133879.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-45356.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54044.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62318.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-62320.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-65094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77355.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-77383.md` — heuristic TIER 3/4
