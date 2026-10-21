# Daily identity and access threats

- **Report date:** 2026-10-19
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-113682

**PIR:** 1.b · **CVSS:** 9.1

Networknt light-4j from 2.1.5 before 2.4.0 contains an authentication bypass vulnerability in BasicAuthHandler that allows unauthenticated attackers to log in as LDAP/AD-delegated users. Attackers can send a Basic Authorization header with a known username and empty password, triggering an unauthenticated LDAP bind that is accepted as successful authentication.

## CVE-2026-80312

**PIR:** 1.b · **CVSS:** 8.2

Improper Authentication vulnerability in Apache Camel OAuth component.



This issue affects Apache Camel: from 4.11.0 before 4.18.5, from 4.19.0 before 4.22.1.



The camel-oauth processors that guard a route did not stop the exchange when authentication could not be completed. Where a failure to establish an authenticated session should have terminated routing and returned an error to the caller, the processors fell through and returned control to the route, so the request continued to the pro

