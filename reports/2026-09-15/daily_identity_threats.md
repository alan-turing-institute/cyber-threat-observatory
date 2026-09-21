# Daily identity and access threats

- **Report date:** 2026-09-15
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-76460

**PIR:** 3.k · **CVSS:** 10.0

A vulnerability in an API of Cisco Identity Services Engine (ISE) could allow an unauthenticated, remote attacker to bypass authentication.

This vulnerability is due to insufficient authentication control on an API endpoint. An attacker could exploit this vulnerability by sending a crafted request to an affected API endpoint. A successful exploit could allow the attacker to gain unauthorized access to the affected device by bypassing the web-based management interface.

## CVE-2026-76461

**PIR:** 3.k · **CVSS:** 9.8

A vulnerability in the email parsing of Cisco AsyncOS Software for Cisco Secure Email Gateway could allow an unauthenticated, remote attacker to execute arbitrary commands with root privileges on the underlying operating system.

This vulnerability is due to insufficient validation in the email parsing logic. An attacker could exploit this vulnerability by sending a crafted email message that contains malicious SQL statements through an affected device. A successful exploit could allow the att

## CVE-2026-71133

**PIR:** 1.b · **CVSS:** 10.0

Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Authentication Engine).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager.  While the vulnerability is in Oracle Access Manager, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in takeo

## CVE-2026-92808

**PIR:** 1.b · **CVSS:** 10.0

A server-side request forgery (SSRF) vulnerability exists in the UnifiedLogin service of Altium Enterprise Server. An unauthenticated network attacker can cause the server to issue outbound HTTP requests to a destination of the attacker's choosing, including internal services that are reachable only from the server itself.




One such internal service exposes server configuration and credential material without authentication, relying only on the request originating locally. Because the forged 

## CVE-2026-83059

**PIR:** 1.b · **CVSS:** 10.0

Vulnerability in the Oracle Internet Directory product of Oracle Fusion Middleware (component: OID LDAP Server).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via LDAP to compromise Oracle Internet Directory.  While the vulnerability is in Oracle Internet Directory, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in

## CVE-2026-20234

**PIR:** 1.b · **CVSS:** 9.9

As part of Cisco's ongoing commitment to proactive security and product quality, the Cisco Identity Services Engine (ISE) and Cisco ISE Passive Identity Connector (ISE-PIC) engineering teams have conducted a comprehensive internal security review. This review resulted in a software hardening release that addresses multiple internally discovered vulnerabilities.

The vulnerabilities tracked by CVE-2026-20234 are related to insufficiently protected credentials issues that are grouped under the C

## CVE-2026-62379

**PIR:** 1.b · **CVSS:** 9.8

Open Access Management (OpenAM) is an access management solution. Prior to 16.1.2, the pre-authentication /authservice PLL endpoint accepts a CustomCallback XML element whose className value selects an arbitrary Java class for AuthXMLUtils to load and instantiate without verifying that it implements DSAMECallbackInterface. Default configurations expose the endpoint without authentication, allowing attacker-controlled class initialization and unsafe deserialization of a serialized Subject value t

