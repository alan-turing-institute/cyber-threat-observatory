# Daily identity and access threats

- **Report date:** 2026-11-23
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-135300

**PIR:** 1.b · **CVSS:** 9.1

Pomerium from 0.30.0 before 0.34.0 contains an authentication bypass vulnerability in the MCP token endpoint that skips client secret verification for client_secret_basic clients. Attackers holding an intercepted authorization code or refresh token can redeem it at /.pomerium/mcp/token with any secret to obtain the victim's access tokens.

## CVE-2026-135163

**PIR:** 1.b · **CVSS:** 9.1

Okou API before 1.762.0 contains a missing authentication vulnerability in its Microsoft Teams, legacy Slack, and GitHub App integration OAuth flows that trusts caller-supplied userId and orgId values. Unauthenticated attackers who know a member's identifiers can complete the flow with their own external account to bind that identity or installation to the victim's Okou user and organization.

## CVE-2026-135157

**PIR:** 1.b · **CVSS:** 8.6

Future AGI before 1.51.0 contains an authentication bypass vulnerability in ACSView.post that allows authenticated members of any organization to take over accounts in other organizations by asserting arbitrary e-mail addresses. Attackers can register a controlled identity provider through IDPUploadViews to obtain sessions as cross-tenant users, and can modify or delete other organizations' identity-provider configurations.

## CVE-2026-135175

**PIR:** 1.b · **CVSS:** 8.6

ZITADEL 4.19.5 before 4.20.3 contains a host header injection vulnerability that allows unauthenticated attackers to redirect notification links by placing a trusted host in the userinfo portion of the x-zitadel-public-host header. Attackers knowing a victim's login name can harvest single-use codes from password-reset links sent to their host, reset passwords, and take over accounts including administrators.

## CVE-2026-96457

**PIR:** 1.b · **CVSS:** 7.7

A flaw was found in the administrative interface of Keycloak, an identity and access management solution. The issue occurs when Fine-Grained Admin Permissions are used to restrict a group administrator from managing specific sub-groups. Due to an incomplete fix for a previous vulnerability, a restricted administrator can bypass these restrictions by moving a forbidden sub-group to the top level of the hierarchy. This allows the attacker to gain unauthorized control over the groups members, poten

