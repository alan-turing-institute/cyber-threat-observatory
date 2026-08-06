# Daily identity and access threats

- **Report date:** 2026-08-05
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-63455

**PIR:** 1.b · **CVSS:** 9.8

Multiple vulnerabilities in the REST API interface of HPE Networking SD-WAN Orchestrator could allow an unauthenticated remote attacker to bypass web authentication mechanisms and access system functions. Successful exploitation could allow an attacker to view and modify potentially sensitive information on the target system.

## CVE-2026-63456

**PIR:** 1.b · **CVSS:** 9.8

Multiple vulnerabilities in the REST API interface of HPE Networking SD-WAN Orchestrator could allow an unauthenticated remote attacker to bypass web authentication mechanisms and access system functions. Successful exploitation could allow an attacker to view and modify potentially sensitive information on the target system.

## CVE-2026-9192

**PIR:** 1.b · **CVSS:** 9.8

An authentication bypass vulnerability in the ODBC App Server of Progress MarkLogic Server before 11.3.6 and 12.0.3 allows an unauthenticated remote attacker to bypass password verification and execute queries with the privileges of any named user known to the server, including administrators.

## CVE-2026-71289

**PIR:** 1.b · **CVSS:** 9.8

The NASA-AMMOS Asynchronous Network Management System (ANMS) reference implementation's default docker-compose.yml publishes the amp-manager service's REST API directly to the host network interface (port 8089, e.g. "${ION_MGR_PORT:-8089}:8089/tcp") with cap_add: NET_ADMIN, NET_RAW, SYS_NICE, bypassing the CAM (Configuration and Access Manager) gateway that is otherwise the system's sole authentication boundary. The underlying REST server, implemented with CivetWeb in JHUAPL/dtnma-tools (src/ref

## CVE-2026-15572

**PIR:** 1.b · **CVSS:** 8.8

A flaw was found in Keycloak's Dynamic Client Registration (DCR) security policy management. The "Allowed Protocol Mapper Types" policy, which restricts which types of data mappers a client can use, fails to re-validate the mapper type during a client update if the mapper's configuration remains unchanged. An attacker with client registration privileges can exploit this by first registering an allowed mapper type with a malicious configuration and then swapping it for a restricted, high-privileg

## CVE-2026-16102

**PIR:** 1.b · **CVSS:** 8.1

A flaw was found in the Dynamic Client Registration (DCR) component of Keycloak, an identity and access management solution. The default DCR policy fails to properly validate the claim path for User Property mappers, allowing them to write values to sensitive internal claim locations. An attacker with a standard user account and a limited Initial Access Token can exploit this to forge administrative roles in their access token. This allows the attacker to take over other clients, steal confident

## CVE-2026-15573

**PIR:** 1.b · **CVSS:** 8.1

A flaw was found in Keycloak's Authorization Services. The component responsible for matching request paths to security policies (PathMatcher) does not properly normalize URIs before comparison. By adding extra characters like a trailing slash or matrix parameters to a URL, an attacker can trick the system into applying a less restrictive security policy than intended. This allows an authenticated user to access administrative or restricted areas they should not have permission to see.

