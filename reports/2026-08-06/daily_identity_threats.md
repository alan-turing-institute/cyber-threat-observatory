# Daily identity and access threats

- **Report date:** 2026-08-06
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-50481

**PIR:** 1.b · **CVSS:** 9.9

Modification of assumed-immutable data (maid) in Azure Active Directory allows an authorized attacker to elevate privileges over a network.

## CVE-2026-59115

**PIR:** 1.b · **CVSS:** 9.9

'.../...//' in Microsoft Entra Provisioning Service (SyncFabric) allows an authorized attacker to elevate privileges over a network.

## CVE-2026-15572

**PIR:** 1.b · **CVSS:** 8.8

A flaw was found in Keycloak's Dynamic Client Registration (DCR) security policy management. The "Allowed Protocol Mapper Types" policy, which restricts which types of data mappers a client can use, fails to re-validate the mapper type during a client update if the mapper's configuration remains unchanged. An attacker with client registration privileges can exploit this by first registering an allowed mapper type with a malicious configuration and then swapping it for a restricted, high-privileg

