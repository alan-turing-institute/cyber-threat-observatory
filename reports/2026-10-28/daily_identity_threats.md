# Daily identity and access threats

- **Report date:** 2026-10-28
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-104384

**PIR:** 1.b · **CVSS:** 8.7

Insufficiently Protected Credentials in tunnel gateway and provisioning interfaces in EagleCloud Aquila versions through 2.6.7.2 on on-premises platforms allows unauthenticated remote attackers to escalate privileges via authentication abuse to access the access keys, secret keys, and deployment secrets

## CVE-2026-59185

**PIR:** 1.b · **CVSS:** 8.5

identrail is a machine identity security platform for AWS, GitHub/OIDC, and Kubernetes. Prior to 1.0.2, the default-on `POST /v1/workspaces/:workspace_id/projects/:project_id/github/connect/complete` endpoint in `internal/api/router.go` accepts `installation_id` from the request body or `X-GitHub-Installation-ID` header without verifying the installation belongs to the caller's workspace. `CompleteGitHubConnection` in `internal/api/github_connect.go` rigorously binds `state` to the caller's tena

## CVE-2026-118669

**PIR:** 1.b · **CVSS:** 8.4

OAuthLib is an implementation of the OAuth request-signing logic for Python 3.6+. Prior to 4.0.0, the client_credentials and Resource Owner Password Credentials token grant handlers can authenticate request.client as one confidential client while retaining an attacker-supplied request.client_id for validate_grant_type and validate_scopes. A lower-privilege authenticated client can therefore cause grant and scope authorization to use another client's identity when an application validator relies 

## CVE-2026-101034

**PIR:** 1.b · **CVSS:** 7.6

An attacker who obtained the hardcoded key could decrypt domain/service account passwords, task run-as credentials, and sysprep passwords stored in or transmitted by GSS Deployment Server installation.

