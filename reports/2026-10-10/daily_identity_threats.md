# Daily identity and access threats

- **Report date:** 2026-10-10
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-78025

**PIR:** 1.b · **CVSS:** 7.5

Dell Secure Connect Gateway (SCG) Policy Manager, versions prior to 5.34.00.16, contains a Missing Authentication for Critical Function vulnerability. An unauthenticated attacker with remote access could potentially exploit this vulnerability, leading to Information disclosure, Protection mechanism bypass, and Unauthorized access.

## CVE-2026-108108

**PIR:** 1.b · **CVSS:** 7.1

PHPNuxBill through 2025.3.20 contains an authentication bypass vulnerability in RADIUS CHAP verification because Password::chap_verify() returns true when the supplied response does not match. Attackers who know a valid customer or PPPoE username can log in through MikroTik hotspot or PPPoE CHAP with any incorrect password to obtain network access and consume that customer's plan.

## CVE-2026-107889

**PIR:** 1.b · **CVSS:** 5.5

A flaw was found in the login theme rendering component of Keycloak. The issue occurs because the security filter responsible for cleaning user input can be bypassed, allowing a realm administrator to store malicious scripts in display fields. This could result in unauthorized JavaScript execution in the browsers of users visiting the login page, potentially leading to data exposure or session interference.

