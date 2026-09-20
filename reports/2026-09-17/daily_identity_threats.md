# Daily identity and access threats

- **Report date:** 2026-09-17
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-76460

**PIR:** 3.k · **CVSS:** 10.0

A vulnerability in an API of Cisco Identity Services Engine (ISE) could allow an unauthenticated, remote attacker to bypass authentication.

This vulnerability is due to insufficient authentication control on an API endpoint. An attacker could exploit this vulnerability by sending a crafted request to an affected API endpoint. A successful exploit could allow the attacker to gain unauthorized access to the affected device by bypassing the web-based management interface.

## CVE-2026-92808

**PIR:** 1.b · **CVSS:** 10.0

A server-side request forgery (SSRF) vulnerability exists in the UnifiedLogin service of Altium Enterprise Server. An unauthenticated network attacker can cause the server to issue outbound HTTP requests to a destination of the attacker's choosing, including internal services that are reachable only from the server itself.




One such internal service exposes server configuration and credential material without authentication, relying only on the request originating locally. Because the forged 

## CVE-2026-20234

**PIR:** 1.b · **CVSS:** 9.9

As part of Cisco's ongoing commitment to proactive security and product quality, the Cisco Identity Services Engine (ISE) and Cisco ISE Passive Identity Connector (ISE-PIC) engineering teams have conducted a comprehensive internal security review. This review resulted in a software hardening release that addresses multiple internally discovered vulnerabilities.

The vulnerabilities tracked by CVE-2026-20234 are related to insufficiently protected credentials issues that are grouped under the C

