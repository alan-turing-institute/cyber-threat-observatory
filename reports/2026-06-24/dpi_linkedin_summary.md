# DPI / LinkedIn daily shortlist

- **Generated (UTC):** 2026-06-25 09:16:19Z
- **Reports folder:** `/root/cyber-threat-observatory/reports/2026-06-24`
- **Included count:** 11

Sorted by **dpi_rank** (desc), then **CVE ID**.

| dpi_rank | Tier | CVE | Why DPI | LinkedIn hook |
|----------|------|-----|---------|----------------|
| 5 | 2 | CVE-2026-46423 | Impacts Digital Identity systems through a SAML authentication bypass that allows full impersonation in enterprise communication platforms. | A critical SAML misconfiguration in Rocket.Chat can allow attackers to fully impersonate any user—including admins—by skipping cryptographic signature verification. This poses a severe risk to enterprise digital identity infrastructure relying on centralized auth mechanisms. |
| 5 | 2 | CVE-2026-56223 | This vulnerability impacts Digital Identity systems through a cross-domain SSO account takeover flaw that allows full access to victim accounts and data via forged SAML assertions. | A critical SSO vulnerability in Capgo enables attackers with enterprise admin access to hijack user accounts across organizations. This highlights the importance of validating identity provider domains during authentication flows, especially in enterprise mobile app management platforms. |
| 5 | 2 | CVE-2026-56270 | Affects Digital Identity infrastructure by exposing cleartext OAuth secrets via an unauthenticated API endpoint, impacting SSO configurations with Google, Microsoft/Azure, GitHub, and Auth0. | A critical missing authentication flaw in Flowise AI allows attackers to harvest OAuth client secrets from any organization—compromising integrations with major identity providers like Google Workspace and Microsoft 365. This poses a serious risk to Digital Identity systems. |
| 4 | 2 | CVE-2026-12537 | Affects CI/CD pipelines with digital identity and access control in software supply chain security contexts. | A critical vulnerability in Google's Gemini CLI allows attackers to execute arbitrary commands in CI environments, potentially compromising secrets and credentials. This impacts Digital Identity sectors where secure authentication and access controls are essential for automated workflows. |
| 4 | 2 | CVE-2026-13164 | Affects Digital Identity sector by enabling unauthenticated account registration and full email data access in a mail marketing platform. | A critical authentication flaw in an email marketing platform could let attackers register accounts and access all stored emails—highlighting the need for secure identity management in digital infrastructure. |
| 4 | 2 | CVE-2026-1840 | Relevant to Digital Identity and Government sectors due to authentication flaws in industrial control systems managing public energy infrastructure. | A critical authentication flaw in smart grid devices could disrupt utility operations. This TIER 2 vulnerability affects Hubbell Aclara Metrum Cellular Web Interface, highlighting risks in government-managed digital public infrastructure like energy grids. |
| 4 | 2 | CVE-2026-45689 | Relevant to Digital Identity due to OAuth integration and ability to bypass authentication for arbitrary users, enabling full administrative access. | A critical pre-authentication NoSQL injection in Rocket.Chat's OAuth endpoint could let attackers impersonate any user and gain full admin control. This impacts digital identity systems that rely on OAuth for authentication. |
| 4 | 2 | CVE-2026-52800 | Affects Digital Identity infrastructure by enabling privilege escalation in Git-based code repositories, which are core to identity management systems. | A CSRF flaw in Gogs allows attackers to escalate privileges within organizations—highlighting the importance of securing internal DevOps tools that manage access control and digital identities. |
| 4 | 2 | CVE-2026-52808 | Affects Digital Identity by compromising repository-level access controls in a Git service used for managing user accounts and permissions. | A Gogs privilege escalation flaw lets write-access collaborators modify admin-only repo settings—highlighting risks in identity management systems where access control misconfigurations can lead to phishing or resource abuse. |
| 4 | 2 | CVE-2026-56256 | Affects Digital Identity systems by bypassing 2FA enforcement in a platform managing user accounts and organization access controls. | A critical 2FA bypass vulnerability in Capgo's ORG management API allows authenticated admins to escalate privileges without proper authentication, undermining digital identity security. This highlights the importance of server-side validation for critical access controls. |
| 3 | 2 | CVE-2026-49980 | Relevant to Digital Identity infrastructure due to potential credential theft and privilege escalation in systems using rclone for file management. | A TIER 2 vulnerability in rclone allows unauthenticated remote command execution when specific flags are enabled. While not exploitable by default, it poses a risk to Digital Identity systems that rely on rclone for cloud storage management. |

## Skipped without LLM (TIER 3/4 heuristic)

- `TIER_3_CVE-2025-71354.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10745.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-10749.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11878.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-11998.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12681.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12760.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12848.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-12849.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13006.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13025.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13026.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13028.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13035.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-13037.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-2050.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-27708.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-33235.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-35025.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-42450.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44016.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-44017.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-46348.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-47110.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48704.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48719.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48720.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48725.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-48731.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49269.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-49851.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-50129.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52794.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-52812.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-53950.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54297.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54639.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54699.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-54904.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55583.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-55759.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-56111.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57281.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-57303.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9643.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9773.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9776.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9777.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9778.md` — heuristic TIER 3/4
- `TIER_3_CVE-2026-9779.md` — heuristic TIER 3/4
