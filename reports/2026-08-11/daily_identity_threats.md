# Daily identity and access threats

- **Report date:** 2026-08-11
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-68067

**PIR:** 1.b · **CVSS:** 9.8

The login endpoint on the Mira cloud API accepts any format-valid string in the password field and returns a live active session token for the account matching the supplied email address. An attacker could use an email address to control cloud accounts and access hormone record information and account settings.

## CVE-2026-26035

**PIR:** 1.b · **CVSS:** 9.8

An Improper Authentication vulnerability [CWE-287] vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.2, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11, FortiWeb 7.2.0 through 7.2.12, FortiWeb 7.0.0 through 7.0.12 may allow a remote unauthenticated attacker to login into the Fortiweb GUI/CLI with a random username and password

## CVE-2026-72920

**PIR:** 1.b · **CVSS:** 9.8

SeaweedFS is a distributed storage system. Prior to 4.24, the filer registers the SeaweedIdentityAccessManagement gRPC service without mandatory authentication when jwt.filer_signing.key is unset, allowing any client that can reach the filer gRPC port to invoke CreateUser, CreateAccessKey, PutPolicy, and related IAM RPCs to mint credentials and gain S3 administrative control. This issue is fixed in versions 4.24.

## CVE-2026-12571

**PIR:** 1.b · **CVSS:** 9.8

An authentication bypass in ManageEngine DDI Central's password-reset workflow allows account takeover.

## CVE-2026-50516

**PIR:** 1.b · **CVSS:** 9.4

Missing authentication for critical function in Microsoft Azure Kubernetes Service allows an unauthorized attacker to elevate privileges over a network.

## CVE-2026-73501

**PIR:** 1.b · **CVSS:** 9.1

kin-openapi is a Go project for handling OpenAPI files. Prior to 0.144.0, ValidationHandler.Load() in openapi3filter/validation_handler.go silently replaces a nil AuthenticationFunc with NoopAuthenticationFunc, which returns nil without checking credentials. This substitution causes every OpenAPI security requirement to be satisfied for unauthenticated requests when an application relies on ValidationHandler as its enforcement middleware. The no-op callback prevents the fail-closed ErrAuthentica

## CVE-2026-72772

**PIR:** 1.b · **CVSS:** 8.9

n8n before 2.32.1 (and before 2.31.5) is vulnerable to account takeover via the Token Exchange Embed Login feature. When a validly-signed incoming token was matched to a local account by its email claim, the service did not verify that the email claim was verified, nor that the trusted key's permitted role ceiling covered that account. As a result, anyone able to obtain a token accepted by a configured trusted key (for example, a trusted issuer emitting unverified email addresses) could authenti

## CVE-2026-72537

**PIR:** 1.b · **CVSS:** 8.8

A privilege escalation vulnerability in Authentik Security authentik through 2026.5.6 allows an attacker with a source-scoped SCIM provisioning token to take over any user account including superusers by provisioning a SCIM user that matches an existing local user by username. The SCIM user ingest function adopts pre-existing local accounts by username without validating scope boundaries. An attacker can rewrite or delete any account, including the superuser, using only a limited provisioning cr

