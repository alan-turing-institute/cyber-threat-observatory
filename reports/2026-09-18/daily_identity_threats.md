# Daily identity and access threats

- **Report date:** 2026-09-18
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-88952

**PIR:** 1.b · **CVSS:** 9.1

Improper Authentication vulnerability in team-alembic AshAuthentication allows an attacker to be signed in as another user by linking an OAuth2 identity to an account that is not theirs.

AshAuthentication.Strategy.OAuth2.UserResolver.resolve/3 matches an existing account using the register action's upsert_identity keys, then gates linking the incoming provider identity to it on email_trusted?/2, which reads only the provider's email_verified boolean and never compares the provider's email value

## CVE-2026-75878

**PIR:** 1.b · **CVSS:** 9.1

IBM Sterling File Gateway could allow a remote attacker to bypass authentication and obtain a fully authenticated session due to improper authentication via an unvalidated SSO header.

## CVE-2026-14850

**PIR:** 1.b · **CVSS:** 8.8

The password reset funcionality is vulnerable to unauthorized account modification due to improper validation of the user_id parameter. An attacker can manipulate this predictable numeric identifier to reset passwords for arbitrary users without proving account ownership.

