# Daily identity and access threats

- **Report date:** 2026-09-09
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-86464

**PIR:** 1.b · **CVSS:** 9.9

In the current development version of Eclipse aeriOS, for which no official release has yet been published, the Identity Manager (IdM) deployment included insecure default configurations and credentials for security-sensitive services.




The Helm chart exposed the Keycloak service and its PostgreSQL backing database through Kubernetes NodePort services by default, while the Docker Compose deployment similarly exposed PostgreSQL on all network interfaces. The deployment included fixed default c

## CVE-2026-83941

**PIR:** 1.b · **CVSS:** 9.9

Missing authorization in Entra ID allows an authorized attacker to elevate privileges over a network.

## CVE-2026-79576

**PIR:** 1.b · **CVSS:** 9.8

An issue in the Single-Sign On (SSO) component of Digital-Infrastructure v9.6.7 allows attackers to authenticate as any user, including the Admin, without a password.

## CVE-2026-87806

**PIR:** 1.b · **CVSS:** 9.1

Parse Server versions <= 8.6.87 and >= 9.0.0 < 9.10.1-alpha.7 contain an authentication bypass in the built-in LDAP authentication adapter. The adapter forwarded the client-supplied password to the directory without verifying that a password had been supplied, and treated any non-error response from the directory as proof of authentication. A zero-length credential turns an LDAP simple bind into the unauthenticated authentication mechanism described in RFC 4513 section 5.1.2, which some director

## CVE-2026-53939

**PIR:** 1.b · **CVSS:** 9.1

OpenIDC/cjose is a C library implementing the Javascript Object Signing and Encryption (JOSE). In versions 0.6.1 through 0.6.2.5, when cjose encrypts a JWE using an AES-CBC-HMAC content-encryption algorithm (`A128CBC-HS256`, `A192CBC-HS384`, or `A256CBC-HS512`) together with any key-management algorithm that generates a fresh content-encryption key (CEK), the CEK is all zero bytes instead of being randomly generated. The resulting JWE is therefore encrypted and authenticated under a fixed, publi

