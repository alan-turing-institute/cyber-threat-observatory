# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-11-22 09:11:40Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-11-21`
- **Included count:** 12

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-134311 | Core authentication library flaw enables account takeover via phone OTP, directly impacting Digital Identity and session management in regulated web applications. | A TIER 2 flaw in the popular `better-auth` library lets attackers hijack accounts via phone OTP by exploiting a missing authorization check. Critical for any team relying on modern web identity stacks to patch before lateral privilege escalation occurs. |
| 5 | 2 | CVE-2026-134312 | Digital Identity sector: critical OAuth authentication flaw in a widely used Node.js library enables account takeover via improper email verification validation. | A critical flaw in the popular Better Auth library allows attackers to hijack user sessions by exploiting OAuth email verification checks. Developers relying on this Node.js IdAM stack should patch immediately to prevent account takeovers. |
| 5 | 2 | CVE-2026-134315 | Core authentication library flaw enabling account takeover via email-change link abuse, directly impacting Digital Identity and session integrity. | A critical flaw in the popular `better-auth` library allows attackers to hijack user sessions and take over accounts through abused email-change links. Organizations relying on this IdAM component for public-facing services should patch immediately to protect user identity and session integrity. |
| 5 | 2 | CVE-2026-134316 | Digital Identity sector: compromises core authentication infrastructure, enabling session forgery, 2FA bypass, and OAuth secret leakage in public-facing identity services. | A TIER 2 flaw in a widely used auth plugin allows attackers to bypass 2FA and forge sessions via cookie validation errors. Organizations using modern identity stacks must patch and rotate secrets to protect critical access controls. |
| 5 | 2 | CVE-2026-134459 | Digital Identity: Timing side-channel in widely-used PHP JWT/JWE library enables CEK recovery, impacting authentication and session management in regulated sectors. | A timing side-channel in a popular PHP JWT library could let attackers decrypt encrypted tokens if RSA1_5 is enabled. While not default, identity providers in gov, finance, and healthcare should audit their crypto configs and patch immediately. |
| 4 | 2 | CVE-2026-134287 | Critical authentication bypass in OpenRemote IoT platform used for smart cities and municipal energy grids, risking unauthorized control of civic actuators (Government/General Infrastructure sector). | Smart city infrastructure relies on secure IoT provisioning—CVE-2026-134287 shows how a missing private-key check in OpenRemote can let attackers impersonate municipal devices and control physical assets. Patching and enforcing mTLS are essential for protecting civic digital infrastructure. |
| 4 | 2 | CVE-2026-134313 | Digital Identity: Race condition in Better Auth library causes session mix-up and account takeover in public-facing authentication endpoints. | A race condition in the Better Auth library can lead to account takeover via session mix-up under concurrent load. While it requires specific database configurations, it underscores the critical need for robust session management in public-facing identity infrastructure. |
| 4 | 2 | CVE-2026-134322 | Digital Identity: Improper authentication in a widely used Node.js IdAM library enables OTP session hijacking and account takeover via an opt-in phone plugin. | Developers using the better-auth library should patch a TIER 2 vulnerability that allows attackers to hijack OTP sign-in flows. This flaw highlights the critical need for strict verification checks in public-facing authentication systems. |
| 4 | 2 | CVE-2026-134370 | TIER 2 authenticated path traversal in Frappe/ERPNext directly impacts Government and Finance DPI deployments, risking exposure of citizen data and financial configurations in public-facing portals. | Frappe/ERPNext underpins numerous citizen service and financial management portals globally. This authenticated path traversal (CVE-2026-134370) could allow attackers to read sensitive credentials and configs—prompt patching is essential for public sector and finance infrastructure. |
| 4 | 2 | CVE-2026-134372 | SQL injection in Frappe ERPNext enables admin session hijacking, directly impacting Finance and Government sectors using this ERP for procurement and financial operations. | ERP platforms power critical public finance and procurement workflows. This TIER 2 SQLi in Frappe ERPNext allows authenticated portal users to escalate to admin privileges, underscoring the risks of internet-exposed enterprise portals. |
| 4 | 2 | CVE-2026-134404 | Finance sector relevance: exposes sensitive procurement, valuation, and margin data in widely deployed ERPNext systems used by regulated and government workflows. | A missing authorization flaw in Frappe ERPNext allows authenticated portal users to bypass permissions and extract sensitive financial and procurement data. Finance and public-sector organizations using ERPNext should patch immediately to protect bidding and valuation confidentiality. |
| 4 | 2 | CVE-2026-134458 | Breaks JWE token confidentiality in widely used PHP JWT libraries, directly impacting SSO, session management, and Digital Identity workflows. | A cryptographic flaw in a popular PHP JWT library can nullify encryption keys for specific JWE configurations, exposing sensitive session and identity claims. Identity providers and regulated services should audit their JWT algorithm selections and patch immediately to protect authentication workflows. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-133983.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134284.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134290.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134291.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134292.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134294.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134295.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134300.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134302.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134307.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134310.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134327.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134329.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134334.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134337.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134338.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134339.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134360.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134361.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134364.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134366.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134367.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134371.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134389.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134393.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134399.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134411.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134418.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134429.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134431.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134432.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134433.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134434.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134435.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134436.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-134453.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-134325.md` — heuristic TIER 3/4
