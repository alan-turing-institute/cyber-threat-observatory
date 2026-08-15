# Daily identity and access threats

- **Report date:** 2026-08-14
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-28008

**PIR:** 1.b · **CVSS:** 9.8

Unauthenticated Broken Authentication in OAuth Single Sign On – SSO (OAuth Client) <= 7.0.0 versions.

## CVE-2026-61967

**PIR:** 1.b · **CVSS:** 9.8

Unauthenticated Privilege Escalation in miniorange otp verification <= 5.5.1 versions.

## CVE-2026-73644

**PIR:** 1.b · **CVSS:** 9.6

OpenDJ is an LDAPv3 compliant directory service. Prior to 5.1.2, the SASL PLAIN authorization identity path in opendj-server-legacy/src/main/java/org/opends/server/extensions/PlainSASLMechanismHandler.java checked the PROXIED_AUTH privilege but did not evaluate the mayProxy proxy ACI scope when an authzid resolved to a different user. Both dn: and u: or bare authzid forms could therefore let an authenticated account holding PROXIED_AUTH assume any resolvable non-root identity outside the identit

## CVE-2026-73302

**PIR:** 1.b · **CVSS:** 9.0

Budibase is an open-source low-code platform. Prior to 3.39.30, the OIDC flow in packages/backend-core/src/middleware/passport/sso/oidc.ts resolved an email without getEmailVerified or an email_verified requirement, and packages/backend-core/src/middleware/passport/sso/sso.ts then used users.getGlobalUserByEmail as a fallback account-linking key. An attacker who can authenticate through a configured identity provider that asserts a victim email as unverified can have a fresh provider identity me

## CVE-2026-72856

**PIR:** 1.b · **CVSS:** 8.6

Budibase versions before 3.40.0 contain an authorization/authentication bypass in the PUT /api/global/users/tenant/owner (changeTenantOwnerEmail) endpoint. On self-hosted instances (SELF_HOSTED or DISABLE_ACCOUNT_PORTAL set), the cloudRestricted middleware is a no-op and the route is protected only by a general authentication check, so any authenticated user — including a lowest-privilege BASIC app user — can reassign the tenant account-holder (top-privilege admin) email to an attacker-controlle

## CVE-2026-0299

**PIR:** 1.b · **CVSS:** 8.5

Local privilege escalation vulnerabilities in the Palo Alto Networks GlobalProtect™ app enable a local user to escalate their privileges to NT AUTHORITY\SYSTEM on Windows, and root on macOS and Linux. This enables a non-administrative user to execute arbitrary commands with administrative privileges.

The GlobalProtect app on iOS, Android, and Chrome OS is not affected.

