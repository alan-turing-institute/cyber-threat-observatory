# Daily identity and access threats

- **Report date:** 2026-10-17
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-111882

**PIR:** 1.b · **CVSS:** 8.6

phpMyFAQ 3.2.0-alpha before 4.1.9 and 4.2.0-alpha before 4.2.0-beta contains an authentication bypass vulnerability that allows IdP-authenticated users to skip TOTP two-factor authentication through the Keycloak and Entra ID SSO callbacks. Attackers holding a valid or phished IdP identity linked to a 2FA-enabled account can complete the OIDC flow and obtain a fully authenticated session, including administrator accounts.

## CVE-2026-111898

**PIR:** 1.b · **CVSS:** 7.7

phpMyFAQ 4.2.0-alpha before 4.2.0-beta contains an authentication bypass vulnerability that allows Keycloak users to take over local accounts by matching preferred_username or email. Attackers controlling a Keycloak identity with a colliding username or unverified email can log in through /auth/keycloak/authorize to bind their subject and gain superadmin privileges.

## CVE-2026-111895

**PIR:** 1.b · **CVSS:** 7.6

phpMyFAQ 3.2.0 before 4.0.0 and 4.0.2 before 4.2.0-beta contains an authentication bypass in its Microsoft Entra ID login flow, which links users by the mutable preferred_username claim and whose AuthEntraId::create() ignores the duplicate-login exception while continuing with the existing local account. Attackers controlling an Entra identity in the configured tenant with a matching preferred_username can take over that local account, including super-admin accounts.

## CVE-2026-104627

**PIR:** 1.b · **CVSS:** 0.0

The Gitea OpenID association callback in the security settings accepted a positive OpenID 2.0 assertion without checking that the signed-in user had started the linking. Because OpenID 2.0 allows unsolicited assertions, an attacker-controlled OpenID provider could attach the attacker's identity to the account of a signed-in victim who opened a crafted link, and the attacker could then sign in as the victim through OpenID login, which does not apply the local TOTP or WebAuthn checks. The callback

