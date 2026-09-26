# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-09-26 02:25:50Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-09-24`
- **Included count:** 19

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-56739 | Directly impacts Digital Identity infrastructure via SSRF in OAuth2/OIDC connectors and webhooks, risking token leakage and cloud metadata theft in public-facing IdP deployments. | Identity providers are the backbone of digital public infrastructure, but misconfigured OAuth connectors can turn them into SSRF gateways. Patching Logto v1.43.0 is critical to prevent token leakage and internal network exposure in enterprise and government IdAM deployments. |
| 5 | 2 | CVE-2026-63203 | Digital Identity: Bypasses OAuth scope enforcement in open-source IdPs, exposing federated SSO tokens and enabling lateral movement to upstream identity providers. | A TIER 2 flaw in Logto reveals how missing OAuth scope enforcement can leak federated SSO tokens, turning low-trust apps into gateways for upstream identity compromise. Critical reading for teams managing open-source IdP deployments. |
| 5 | 2 | CVE-2026-85056 | Digital Identity sector: directly impacts open-source IdPs (ZITADEL) used in regulated/public infrastructure, enabling MFA bypass via OIDC/SAML session reuse. | A TIER 2 MFA bypass in ZITADEL (CVE-2026-85056) threatens public-facing identity providers by allowing session reuse to skip second-factor verification. DPI operators and regulated enterprises using open-source IdPs should enforce Force MFA policies or patch immediately to secure critical authentication gateways. |
| 5 | 2 | CVE-2026-85057 | Digital Identity sector: Compromises core IdP/SSO infrastructure (ZITADEL), breaking multi-tenant isolation and exposing authentication credentials. | A TIER 2 flaw in ZITADEL, a core open-source IdP/SSO platform, enables authenticated org admins to bypass multi-tenant isolation and extract bootstrap credentials. DPI operators and regulated enterprises should patch to v3.4.13/v4.16.1 immediately to safeguard identity pipelines. |
| 5 | 2 | CVE-2026-88907 | Authentication bypass in Turkey's national academic SSO (Yetkim) integration undermines Digital Identity and Government/public research infrastructure trust. | A TIER 2 SAML authentication bypass in Turkey’s national academic SSO infrastructure highlights the critical need for strict assertion validation in public-sector digital identity systems. How are you hardening Shibboleth/SSO flows against ePPN manipulation? |
| 5 | 2 | CVE-2026-91187 | Critical JWT signature bypass in a Cloudflare Zero Trust integration library, directly compromising authentication and identity verification for public-facing digital services. | Zero Trust isn't zero risk: a critical JWT verification flaw in a popular Elixir library allows unauthenticated attackers to forge service tokens and bypass authentication entirely. Teams relying on Cloudflare-backed identity flows should patch immediately to protect public-facing digital services. |
| 5 | 2 | CVE-2026-94606 | Directly impacts Digital Identity infrastructure by enabling MFA hijacking and full account takeover in the authentik open-source IdP/SSO gateway. | A critical flaw in the open-source identity provider authentik allows attackers with valid credentials to bypass MFA during enrollment, leading to full account takeover. Organizations using authentik for SSO and digital identity management must patch immediately to secure downstream services. |
| 5 | 2 | CVE-2026-94611 | Core open-source IdAM/SSO platform (authentik) exposes stored credentials/secrets to authenticated users with view permissions, impacting Digital Identity infrastructure. | Identity providers are the gatekeepers of digital trust. CVE-2026-94611 in authentik reveals how a misconfigured permission can turn a view-only account into a credential exfiltration vector, underscoring that RBAC hardening is just as critical as patching. |
| 5 | 2 | CVE-2026-94612 | Authentication bypass in authentik's SAML Source allows assertion replay and audience restriction bypass, directly impacting enterprise and government digital identity infrastructure. | A TIER 2 flaw in authentik's SAML Source lets attackers replay or misuse valid assertions to bypass authentication. Organizations relying on federated identity must patch immediately to protect their digital identity gateways. |
| 5 | 2 | CVE-2026-94613 | TIER 2 DoS in authentik IdAM platform disrupts SAML authentication workflows, directly impacting Digital Identity infrastructure. | Open-source identity providers like authentik are critical to modern DPI, but a new TIER 2 flaw shows how malformed SAML requests can crash auth workers. Patch or proxy-block SAML endpoints to keep citizen and enterprise logins resilient. |
| 4 | 2 | CVE-2026-13016 | Foundational enterprise ITSM platform with unauthenticated SQLi impacting cross-sector DPI deployments across government, finance, and healthcare. | Critical unauthenticated SQL injection in ServiceNow’s AI Platform exposes foundational enterprise ITSM systems to data breaches. Organizations across government, finance, and healthcare must prioritize patching to protect cross-sector digital services. |
| 4 | 2 | CVE-2026-56744 | Finance sector: silent fund redirection in cryptocurrency wallet infrastructure via compromised storage provider. | Cryptocurrency wallets relying on remote storage face silent fund redirection risks when transaction outputs aren't validated client-side. This TIER 2 flaw highlights the critical need for defense-in-depth in digital finance infrastructure, even when authentication is intact. |
| 4 | 2 | CVE-2026-86858 | Unauthenticated data manipulation in ServiceNow AI Platform threatens data integrity for Government and Finance deployments handling citizen services and operational workflows. | ServiceNow’s AI Platform faces a TIER 2 access control flaw allowing unauthenticated data tampering, posing direct risks to Government and Finance agencies relying on it for citizen services and case management. Prompt patching and enhanced audit logging are critical to safeguarding public data integrity. |
| 4 | 2 | CVE-2026-86859 | Unauthenticated authorization bypass in ServiceNow AI Platform, extensively deployed across government agencies for citizen services and ITSM, with secondary relevance to finance and healthcare. | An unauthenticated authorization bypass in ServiceNow’s AI Platform (CVE-2026-86859) threatens sensitive data across government, finance, and healthcare deployments. Public sector agencies relying on ServiceNow for citizen services should prioritize immediate patching to secure critical digital infrastructure. |
| 4 | 2 | CVE-2026-86860 | Unauthenticated privilege escalation in ServiceNow AI Platform impacts Government, Finance, and Healthcare deployments relying on it for IT service management and automation. | Critical unauthenticated flaw in ServiceNow AI Platform exposes sensitive instance data and enables privilege escalation. Government and enterprise ITSM deployments must verify self-hosted patches immediately. |
| 4 | 2 | CVE-2026-93782 | Foundational Linux kernel hypervisor flaw enabling guest-to-host escape, directly impacting cloud and government IT infrastructure resilience. | A TIER 2 Linux kernel flaw in vhost-scsi allows compromised VMs to escape to the host, threatening the foundational hypervisor layer of national cloud and government infrastructure. Patching or disabling vhost-scsi is critical for multi-tenant DPI environments. |
| 4 | 2 | CVE-2026-97404 | OpenStack Zaqar authentication bypass impacts cloud infrastructure widely deployed in government, healthcare, and finance sectors. | Cloud infrastructure security remains critical for digital public services. This Tier 2 vulnerability in OpenStack Zaqar's Keystone authentication highlights the need for rigorous internal microservice hardening in regulated cloud environments. |
| 3 | 2 | CVE-2026-57178 | Impacts Digital Identity via authentication bypass in a widely used social login library, enabling arbitrary account takeover through flawed OAuth2 callback verification. | Social login shortcuts can become backdoors: a signature bypass in python-social-auth allows attackers to hijack accounts by skipping OAuth verification. Patching identity stacks remains critical for public and enterprise services. |
| 3 | 2 | CVE-2026-78312 | Impacts industrial energy management systems deployed by government utilities and critical infrastructure operators, posing lateral movement risks in OT networks. | Unauthenticated path traversal in Delta Electronics' DIAEnergie energy management software highlights the persistent risks in OT/ICS environments. Even when air-gapped, internal vulnerabilities can enable rapid lateral movement for compromised industrial networks. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2026-12559.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13466.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13467.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14443.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-14780.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-19072.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-4638.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57590.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58004.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58005.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58006.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58007.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-58008.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61823.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-61825.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63493.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-63498.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-71540.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-7169.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78308.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78309.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-78311.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-79680.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81473.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81539.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81545.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81547.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81548.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81549.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-81552.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82077.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82093.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82094.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82157.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82164.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-82372.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-86857.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87721.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-87722.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-89325.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-90959.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91123.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-91160.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93207.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93221.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93224.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93228.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93229.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93237.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93250.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93260.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93262.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93265.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93277.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93280.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93282.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93284.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93287.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93288.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93425.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93543.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93786.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93787.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93790.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93793.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93796.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93798.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93801.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93806.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93810.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93813.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93816.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93817.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93826.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93827.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-93830.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95519.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95521.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-95985.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96744.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96746.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96748.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96750.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-96883.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97056.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97057.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97059.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97324.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97409.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97415.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97417.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97421.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97428.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97429.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97433.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97437.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97438.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97442.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97444.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97445.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97448.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97451.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97452.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97454.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97455.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97478.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97496.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97497.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97508.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97509.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97513.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-97520.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-93225.md` — heuristic TIER 3/4
- `TIER_4_CVE-2026-97474.md` — heuristic TIER 3/4
