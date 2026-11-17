# Daily identity and access threats

- **Report date:** 2026-11-16
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-129483

**PIR:** 1.b · **CVSS:** 9.3

Cyrus SASL through 2.1.28 contains an authentication bypass vulnerability in the SRP server mechanism because srp_server_mech_step2 does not reject client public values A that are multiples of N. Unauthenticated network clients can send A equal to N to force a zero shared secret, authenticating as any existing user without the password and learning session keys.

## CVE-2026-129349

**PIR:** 1.b · **CVSS:** 9.1

When authentication caching is enabled on DefaultLdapRealm, after a user logs in successfully once, subsequent logins for that user succeed with any password.
A cached authentication skips the LDAP bind, and the AllowAllCredentialsMatcher installed by default in DefaultLdapRealm accepts any credentials, allowing an attacker who knows a valid username to authenticate as that user.
This issue affects all Apache Shiro versions through 3.0.0, only when using DefaultLdapRealm (or JndiLdapRealm) with 

## CVE-2026-74762

**PIR:** 1.b · **CVSS:** 5.9

Apache Shiro is vulnerable to session fixation when a user is authenticated via the "Remember me" functionality. In affected versions, when a subject is restored from a "Remember me" cookie, the existing session is not invalidated, nor is a new session created with a new ID.
Additionally, session IDs were accepted from the request URL even when session ID URL rewriting was disabled.
This issue affects all Apache Shiro versions through 3.0.0, only when RememberMe functionality is enabled.

Mitiga

## CVE-2026-129347

**PIR:** 1.b · **CVSS:** 2.3

`DefaultPasswordService` and `SimpleCredentialsMatcher` could treat an empty stored credential as a match for an empty submitted password.
This issue affects all Apache Shiro versions through 3.0.1, only when accounts with an empty stored credential exist.

Mitigation: Upgrade to version 3.0.2 or later, which fixes the issue.
Alternatively, avoid storing empty credentials, and reject empty passwords in the application.

