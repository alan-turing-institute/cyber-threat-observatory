# Daily identity and access threats

- **Report date:** 2026-10-29
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-84295

**PIR:** 1.b · **CVSS:** 10.0

Improper authentication in Progress Software WS_FTP Server versions prior to 2024.0.6 and 2025.0.3 on Windows could allow an unauthenticated remote attacker to access sensitive information, including administrative credentials.

## CVE-2026-92744

**PIR:** 1.b · **CVSS:** 8.7

Under certain conditions, privilege manager agent allows a remote unauthenticated attacker to execute
arbitrary code as LocalSystem.

## CVE-2026-119127

**PIR:** 1.b · **CVSS:** 8.6

ZITADEL 4.0.0 before 4.19.5 contains a host header injection vulnerability in the Login V2 UI that allows unauthenticated attackers to poison password-reset, invite, and email-verification links by supplying untrusted x-zitadel-public-host, x-zitadel-forward-host, or x-forwarded-host headers. Attackers knowing a victim's login name can point the links in genuine emails at their host, harvest the single-use codes when the links are opened, and take over accounts including instance administrators.

## CVE-2026-59185

**PIR:** 1.b · **CVSS:** 8.5

identrail is a machine identity security platform for AWS, GitHub/OIDC, and Kubernetes. Prior to 1.0.2, the default-on `POST /v1/workspaces/:workspace_id/projects/:project_id/github/connect/complete` endpoint in `internal/api/router.go` accepts `installation_id` from the request body or `X-GitHub-Installation-ID` header without verifying the installation belongs to the caller's workspace. `CompleteGitHubConnection` in `internal/api/github_connect.go` rigorously binds `state` to the caller's tena

## CVE-2026-118669

**PIR:** 1.b · **CVSS:** 8.4

OAuthLib is an implementation of the OAuth request-signing logic for Python 3.6+. Prior to 4.0.0, the client_credentials and Resource Owner Password Credentials token grant handlers can authenticate request.client as one confidential client while retaining an attacker-supplied request.client_id for validate_grant_type and validate_scopes. A lower-privilege authenticated client can therefore cause grant and scope authorization to use another client's identity when an application validator relies 

## CVE-2025-14260

**PIR:** 1.b · **CVSS:** 8.3

Due to the improper implementation of access control rules, the WSO2 product accepts user-supplied input related to resource location without enforcing expected validation constraints. This can be exploited by an unauthenticated actor to direct the server to make requests to arbitrary network locations.

Exploiting this vulnerability allows a malicious actor to access both internal and external resources, available through the network or filesystem, that are reachable by the WSO2 product. This c

## CVE-2026-45049

**PIR:** 1.b · **CVSS:** 8.3

Open Access Management (OpenAM) is an access management solution. Prior to 16.1.1, the `Cross-Domain Single Sign-On` (`CDSSO`) servlet allows a logged-in user's raw OpenAM session token to be POSTed to an attacker-controlled URL. An attacker who induces an authenticated victim to visit a crafted URL can receive the session credential and potentially hijack the session. Deployments must have `CDSSO` enabled, as is common in multi-domain deployments, and exploitation is additionally gated on a non

