# Daily identity and access threats

- **Report date:** 2026-09-08
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-83941

**PIR:** 1.b · **CVSS:** 9.9

Missing authorization in Entra ID allows an authorized attacker to elevate privileges over a network.

## CVE-2026-86464

**PIR:** 1.b · **CVSS:** 9.9

In the current development version of Eclipse aeriOS, for which no official release has yet been published, the Identity Manager (IdM) deployment included insecure default configurations and credentials for security-sensitive services.




The Helm chart exposed the Keycloak service and its PostgreSQL backing database through Kubernetes NodePort services by default, while the Docker Compose deployment similarly exposed PostgreSQL on all network interfaces. The deployment included fixed default c

## CVE-2026-76578

**PIR:** 1.b · **CVSS:** 9.8

A flaw was found in FreeIPA. The self-managed OTP token ACI does not require authentication and does not restrict which attributes may be added alongside the token entry. An unauthenticated LDAP client can exploit this, combined with a related flaw in the underlying directory server's ACI evaluation (tracked separately), to create an arbitrary attacker-controlled Kerberos principal and have it added to the administrators group. This allows a remote, unauthenticated attacker to obtain genuine Fre

## CVE-2026-79576

**PIR:** 1.b · **CVSS:** 9.8

An issue in the Single-Sign On (SSO) component of Digital-Infrastructure v9.6.7 allows attackers to authenticate as any user, including the Admin, without a password.

## CVE-2026-18922

**PIR:** 1.b · **CVSS:** 9.8

A flaw was found in 389 Directory Server. During SASL PLAIN authentication, a stale identity carried in a Cyrus SASL auxiliary property from a prior failed bind attempt can be installed on a connection following a subsequent, unrelated successful bind, regardless of which SASL mechanism completes that second bind. An attacker can send a SASL PLAIN bind as cn=Directory Manager with an incorrect password, then complete a SASL ANONYMOUS bind on the same connection, causing the server to grant Direc

