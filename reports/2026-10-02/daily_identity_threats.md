# Daily identity and access threats

- **Report date:** 2026-10-02
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-76142

**PIR:** 1.b · **CVSS:** 9.3

Insufficient authentication and access control on the internal-only IPC SOAP endpoint of the Genian NAC/ZTNA policy server allows an unauthenticated attacker to invoke internal functions

## CVE-2026-94276

**PIR:** 1.b · **CVSS:** 5.1

Improper Authentication vulnerability in Apache APISIX.

On a route using openid-connect plugin with remote introspection against an authorization server that serves multiple issuers, a token that introspects as active for one issuer may get accepted on a route restricted to another. This issue affects Apache APISIX: from 3.12.0 through 3.18.0.

Users are recommended to upgrade to version 3.19.0, which fixes the issue.

## CVE-2026-103877

**PIR:** 1.b · **CVSS:** 0.0

Deserialization of Untrusted Data vulnerability in Apache Directory LDAP API.



A rogue/compromised LDAP server (or pre-TLS MITM) can answer a client's loadSchema() subschema search with a schema object that contains a serialized Java class, allowing some potential RCE. 



This issue affects Apache Directory LDAP API: from 2.1.0 before 2.1.9.



Users are recommended to upgrade to version 2.1.9, which fixes the issue.

