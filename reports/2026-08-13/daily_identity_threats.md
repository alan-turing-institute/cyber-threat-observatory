# Daily identity and access threats

- **Report date:** 2026-08-13
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-28008

**PIR:** 1.b · **CVSS:** 9.8

Unauthenticated Broken Authentication in OAuth Single Sign On – SSO (OAuth Client) <= 7.0.0 versions.

## CVE-2026-61967

**PIR:** 1.b · **CVSS:** 9.8

Unauthenticated Privilege Escalation in miniorange otp verification <= 5.5.1 versions.

## CVE-2026-26035

**PIR:** 1.b · **CVSS:** 9.8

An Improper Authentication vulnerability [CWE-287] vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.2, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11, FortiWeb 7.2.0 through 7.2.12, FortiWeb 7.0.0 through 7.0.12 may allow a remote unauthenticated attacker to login into the Fortiweb GUI/CLI with a random username and password

## CVE-2026-73644

**PIR:** 1.b · **CVSS:** 9.6

OpenDJ is an LDAPv3 compliant directory service. Prior to 5.1.2, the SASL PLAIN authorization identity path in opendj-server-legacy/src/main/java/org/opends/server/extensions/PlainSASLMechanismHandler.java checked the PROXIED_AUTH privilege but did not evaluate the mayProxy proxy ACI scope when an authzid resolved to a different user. Both dn: and u: or bare authzid forms could therefore let an authenticated account holding PROXIED_AUTH assume any resolvable non-root identity outside the identit

## CVE-2026-14525

**PIR:** 1.b · **CVSS:** 9.4

IBM WebSphere Application Server - Liberty 17.0.0.3 through 26.0.0.8 IBM WebSphere Application Server Liberty is vulnerable to an authentication bypass when the rtcomm-1.0 or rtcommGateway-1.0 feature is enabled.

## CVE-2026-73302

**PIR:** 1.b · **CVSS:** 9.0

Budibase is an open-source low-code platform. Prior to 3.39.30, the OIDC flow in packages/backend-core/src/middleware/passport/sso/oidc.ts resolved an email without getEmailVerified or an email_verified requirement, and packages/backend-core/src/middleware/passport/sso/sso.ts then used users.getGlobalUserByEmail as a fallback account-linking key. An attacker who can authenticate through a configured identity provider that asserts a victim email as unverified can have a fresh provider identity me

