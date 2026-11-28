# Daily identity and access threats

- **Report date:** 2026-11-27
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-123903

**PIR:** 1.b · **CVSS:** 9.8

VMware vCenter contains an authentication bypass vulnerability in the VMware Directory Service. Broadcom has evaluated the severity of this issue to be in the Critical severity range with a maximum CVSSv3 base score of 9.8.
Affected versions:
VMware vCenter Server 9.1.x.x: fixed in 9.1.2
VMware vCenter Server 9.0.x.x: fixed in 9.0.2.0300
VMware vCenter Server 8.0: fixed in 8.0 U3m
VMware Cloud Foundation 5.x: fixed in 5.2.5
VMware Telco Cloud Platform 3.0: fixed in KB463501
VMware Telco Cloud Pl

## CVE-2026-135384

**PIR:** 1.b · **CVSS:** 9.2

Improper authentication in OIDC bearer token verification in Canonical LXD before 5.0.12, 5.21.10, 6.10.2 allows a remote attacker holding a token signed by the configured identity provider to authenticate to the LXD API and gain unauthorized control or impersonate users via presenting tokens issued for other applications, ID tokens, or unverified email claims.

## CVE-2026-137523

**PIR:** 1.b · **CVSS:** 8.8

ToolJet before 3.21.96-LTS contains an authentication bypass in instance-level Google SSO because the id_token audience is not verified when no Google OAuth client ID is configured, the shipped default. Unauthenticated attackers can submit a Google-signed id_token minted for their own OAuth client to /api/sso/sign-in/common/google without an organizationId, obtaining a session as any existing user with the matching email.

## CVE-2026-137478

**PIR:** 1.b · **CVSS:** 8.7

Traefik before 2.11.62, 3.x before 3.7.18, and 3.8.0-rc.1 contain an authentication bypass in the ForwardAuth middleware because connection isolation for NTLM and Negotiate credentials checks only the Authorization header, not Proxy-Authorization. Unauthenticated attackers can send such credentials in Proxy-Authorization to reuse a shared authentication-server connection already authenticated by another user, receive that user's identity via authResponseHeaders, and access backends as that user.

## CVE-2026-137552

**PIR:** 1.b · **CVSS:** 8.7

Frappe Framework before 15.121.1 and 16.x before 16.35.0 accepts an undocumented OAuth2 Resource Owner Password Credentials (password) grant at its token endpoint, which does not enforce two-factor authentication or forced password resets. An attacker with a user's valid credentials can use this grant to obtain a full-access OAuth token, bypassing 2FA.

## CVE-2026-137457

**PIR:** 1.b · **CVSS:** 8.7

FreeRDP from 3.0.0 before 3.33.0 contains a missing authentication vulnerability in the shadow server's fast-path input handlers in fastpath.c that allows unauthenticated attackers to inject input before activation. Attackers can negotiate TLS-only RDP, skip Confirm Active, and send Fast-Path Input Event PDUs to inject keystrokes and mouse movement into the host X11 session via XTEST.

## CVE-2026-124842

**PIR:** 1.b · **CVSS:** 8.3

SEPPmail Secure Email Gateway before 15.1.2 exposes legacy GINA password-reset paths that can replace a registered account credential without authenticating the requester. A remote attacker who knows the account address can force a reset when a configured administrator or valid stored creator is present, disrupting access and revoking active API tokens; the replacement credential is sent only to a pre-existing trusted recipient.

## CVE-2026-80500

**PIR:** 1.b · **CVSS:** 7.7

Dell Secure Connect Gateway - Virtual Edition, versions prior to 5.36.00.16, contains an Improper Authentication vulnerability. An unauthenticated local attacker could potentially exploit this vulnerability, leading to Unauthorized access.

## CVE-2026-52803

**PIR:** 1.b · **CVSS:** 7.6

Gogs is an open source self-hosted Git service. Prior to 0.15.0, Gogs does not regenerate the session ID after successful authentication. An attacker who forces a victim to use a known session ID can hijack the session after the victim logs in and take over the account. This issue is fixed in version 0.15.0.

