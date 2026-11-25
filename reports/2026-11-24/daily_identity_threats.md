# Daily identity and access threats

- **Report date:** 2026-11-24
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-124284

**PIR:** 1.b · **CVSS:** 9.8

A critical security vulnerability affects certain authentication methods in Genetec Security Center, including external identity providers using OpenID Connect (OIDC) or SAML 2.0, and Active Directory Federation Services (AD FS) using WS-Trust or WS-Federation.
Under specific conditions, successful exploitation may allow an unauthenticated attacker to gain unauthorized access to the system with the privileges of an affected user. Successful exploitation requires a specific combination of conditi

## CVE-2026-135300

**PIR:** 1.b · **CVSS:** 9.1

Pomerium from 0.30.0 before 0.34.0 contains an authentication bypass vulnerability in the MCP token endpoint that skips client secret verification for client_secret_basic clients. Attackers holding an intercepted authorization code or refresh token can redeem it at /.pomerium/mcp/token with any secret to obtain the victim's access tokens.

## CVE-2026-135163

**PIR:** 1.b · **CVSS:** 9.1

Okou API before 1.762.0 contains a missing authentication vulnerability in its Microsoft Teams, legacy Slack, and GitHub App integration OAuth flows that trusts caller-supplied userId and orgId values. Unauthenticated attackers who know a member's identifiers can complete the flow with their own external account to bind that identity or installation to the victim's Okou user and organization.

## CVE-2026-136165

**PIR:** 1.b · **CVSS:** 9.1

Fider before 0.40.0 contains an account takeover vulnerability that allows unauthenticated attackers to sign in as existing users by linking OAuth identities through unverified email matches. Attackers can use a Google account carrying an unverified copy of a victim's email, including a tenant administrator's, to bind their identity via the OAuthToken handler and obtain persistent session access.

## CVE-2026-117593

**PIR:** 1.b · **CVSS:** 9.1

Weak Password Recovery Mechanism for Forgotten Password vulnerability in ITG Bilgisayar Teknoloji Grubu Tic. Ltd. Şti. VSRM allows Password Recovery Exploitation.

This issue affects vSRM: from v14.08.3 before v14.08.5.

