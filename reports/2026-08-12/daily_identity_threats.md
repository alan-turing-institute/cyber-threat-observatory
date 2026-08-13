# Daily identity and access threats

- **Report date:** 2026-08-12
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-26035

**PIR:** 1.b · **CVSS:** 9.8

An Improper Authentication vulnerability [CWE-287] vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.2, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11, FortiWeb 7.2.0 through 7.2.12, FortiWeb 7.0.0 through 7.0.12 may allow a remote unauthenticated attacker to login into the Fortiweb GUI/CLI with a random username and password

## CVE-2026-72920

**PIR:** 1.b · **CVSS:** 9.8

SeaweedFS is a distributed storage system. Prior to 4.24, the filer registers the SeaweedIdentityAccessManagement gRPC service without mandatory authentication when jwt.filer_signing.key is unset, allowing any client that can reach the filer gRPC port to invoke CreateUser, CreateAccessKey, PutPolicy, and related IAM RPCs to mint credentials and gain S3 administrative control. This issue is fixed in versions 4.24.

## CVE-2026-12571

**PIR:** 1.b · **CVSS:** 9.8

An authentication bypass in ManageEngine DDI Central's password-reset workflow allows account takeover.

## CVE-2026-72537

**PIR:** 1.b · **CVSS:** 8.8

A privilege escalation vulnerability in Authentik Security authentik through 2026.5.6 allows an attacker with a source-scoped SCIM provisioning token to take over any user account including superusers by provisioning a SCIM user that matches an existing local user by username. The SCIM user ingest function adopts pre-existing local accounts by username without validating scope boundaries. An attacker can rewrite or delete any account, including the superuser, using only a limited provisioning cr

## CVE-2026-72534

**PIR:** 1.b · **CVSS:** 8.8

A privilege escalation vulnerability in Authentik Security authentik through 2026.5.6 allows an attacker with a source-scoped SCIM provisioning token to gain superuser privileges by provisioning a SCIM group that matches an existing administrator group by name. The SCIM group ingest function adopts any existing group by name and replaces its membership without validating the source scope against the target group. An attacker can grant their provisioning token full IdP superuser access and lock o

