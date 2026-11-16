# Daily identity and access threats

- **Report date:** 2026-11-15
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-129483

**PIR:** 1.b · **CVSS:** 9.3

Cyrus SASL through 2.1.28 contains an authentication bypass vulnerability in the SRP server mechanism because srp_server_mech_step2 does not reject client public values A that are multiples of N. Unauthenticated network clients can send A equal to N to force a zero shared secret, authenticating as any existing user without the password and learning session keys.

## CVE-2026-129349

**PIR:** 1.b · **CVSS:** 9.1

When authentication caching is enabled on DefaultLdapRealm, after a user logs in successfully once, subsequent logins for that user succeed with any password.
A cached authentication skips the LDAP bind, and the AllowAllCredentialsMatcher installed by default in DefaultLdapRealm accepts any credentials, allowing an attacker who knows a valid username to authenticate as that user.
This issue affects all Apache Shiro versions through 3.0.0, only when using DefaultLdapRealm (or JndiLdapRealm) with 

## CVE-2026-129360

**PIR:** 1.b · **CVSS:** 7.3

A weakness has been identified in Linux Foundation Magma up to 1.9.0. The impacted element is an unknown function of the file orc8r/cloud/go/services/obsidian/access/operator.go of the component Obsidian REST. Executing a manipulation of the argument X-Magma-Client-Cert-Serial can lead to authentication bypass by spoofing. The attack can be launched remotely. The vendor was contacted early about this disclosure but did not respond in any way.

