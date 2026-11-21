# Daily identity and access threats

- **Report date:** 2026-11-20
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-129073

**PIR:** 3.k · **CVSS:** 9.8

Authentication Bypass Using an Alternate Path or Channel vulnerability in miniOrange miniorange otp verification miniorange-otp-verification allows Authentication Abuse.This issue affects miniorange otp verification: from n/a through 5.6.1.

## CVE-2026-127027

**PIR:** 3.k · **CVSS:** 9.2

Poste.io is vulnerable to remote code execution in DMARC report processing. Email sent to dmarc-reports@<domain> is saved without sender verification. Script that runs as root unpacks the attachments using unsafe shell commands, allowing command injection through crafted attachments (e.g. file names or archive contents). A remote unauthenticated attacker who can send an email to the server's port 25 can execute arbitrary commands as root within the Poste.io container.


This issue was fixed in v

## CVE-2026-130235

**PIR:** 1.b · **CVSS:** 8.7

In the Okta .NET SDK Abstractions library, outbound HTTP requests are not restricted to the configured Okta organization domain when processing certain URL formats. If a URL parameter is modified to specify an external host, the library may transmit the configured SSWS API token to that unintended destination.

## CVE-2026-133659

**PIR:** 1.b · **CVSS:** 8.6

Flowintel contains multiple SSO identity and organisation trust boundary violations that collectively allow account takeover, privilege escalation, and unauthorized access to private case data.

- Keycloak SSO accepted unverified email claims, and all SSO providers (Keycloak, Entra ID, SimpleSAML) could resolve a claimed email address to an existing account that was created via a different sign-in method, enabling cross-provider account collision and unauthorized access to another user's account

## CVE-2026-115342

**PIR:** 1.b · **CVSS:** 8.5

Argument injection in OpenVPN version 2.4.0 through 2.6.23 and 2.7_alpha1 through 2.7.8 on Windows allows local authenticated users to bypass interactive service option validation and add arbitrary configuration options via a crafted command line.

## CVE-2026-130151

**PIR:** 1.b · **CVSS:** 8.5

Okta Privileged Access (OPA) Gateway includes a version of the FreeRDP library affected by memory management issues in its smartcard redirection handling. When an RDP session is established meeting specific session criteria, command execution within the context of the local Gateway service account may be allowed.

## CVE-2026-130179

**PIR:** 1.b · **CVSS:** 8.5

The Okta .NET SDK Abstractions library systematically writes per-request authentication credentials to a shared HTTP client instance, rather than being isolated to individual outbound request objects. When using scoped child clients, a subsequent scoped request can overwrite the shared client configuration. Because the original parent client credential has not been restored, subsequent outbound requests may be transmitted using the newly written credential, which can result in subsequent actions

## CVE-2026-130236

**PIR:** 1.b · **CVSS:** 8.5

In the Auth0 Authorization Extension, request authentication handling can process claims from query parameters independently of header validation. Under specific preconditions, this may allow an authenticated tenant user to issue requests to the extension's administrative endpoints. Also, input handling during rule generation may permit modification of the tenant login rule published by the extension.

## CVE-2026-55216

**PIR:** 1.b · **CVSS:** 8.1

Logto is the modern, open-source auth infrastructure for SaaS and AI apps. Prior to 1.46.0, social account linking can use an unverified email returned by the standard OAuth 2.0 or Azure AD connector to select an existing local account. When findSocialRelatedUser matches a victim's email and a request to POST /api/experience/identification enables linkSocialIdentity, an attacker who controls that unverified provider email can link an attacker-controlled social identity to the victim account and 

## CVE-2026-130234

**PIR:** 1.b · **CVSS:** 8.0

The Okta Swift Management SDK does not percent-encode forward slash (/) characters during path parameter interpolation. If an application supplies input containing relative path sequences (e.g., ../) to an SDK method, standard URL normalization may direct the outbound request to an alternative Okta Management API endpoint.

