# Daily identity and access threats

- **Report date:** 2026-08-25
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-77998

**PIR:** 1.b · **CVSS:** 10.0

Joomla Extension - miniorange.com - Unauthenticated Authentication Bypass via SAMLResponse Parameter in miniOrange SAML SSO < 11.0.2, SAML SP Single Sign On – Login with ADFS < 6.4,  SAML SP Single Sign On – SAML SSO login with Google Apps < 6.4 - This is due to the mo_saml_validate_signature() function performing a loose boolean check on the raw tri-state integer returned by PHP's openssl_verify(), causing an error return value of -1 to be evaluated as truthy and therefore treated as a successf

## CVE-2026-55640

**PIR:** 1.b · **CVSS:** 9.1

Nextcloud MCP Server is a production-ready MCP server that connects AI assistants to a Nextcloud instance. Prior to 0.117.2, the POST /webhooks/nextcloud endpoint in nextcloud_mcp_server/vector/webhook_receiver.py has no authentication by default because WEBHOOK_SECRET defaults to None and startup validation does not require it. When WEBHOOK_SECRET is unset, handle_nextcloud_webhook() accepts unauthenticated requests. The payload["user"]["uid"] field parsed in nextcloud_mcp_server/vector/webhook

## CVE-2026-80192

**PIR:** 1.b · **CVSS:** 8.6

@better-auth/sso before 1.6.27 (and before 1.4.8 in the 1.4.x line and before 1.7.0-rc.5 in the 1.7 prerelease line) contains two domain-ownership flaws. When domain verification is disabled, automatic organization assignment accepts unverified provider domains, allowing an authenticated organization owner/administrator to register an SSO provider for an arbitrary domain and have users with matching email domains added to the attacker's organization with default member permissions. When domain v

## CVE-2026-65633

**PIR:** 1.b · **CVSS:** 7.6

Improper Authentication vulnerability in team-alembic AshAuthentication allows purpose-limited JWTs to be replayed as full bearer API credentials when a resource uses stateless bearer-token verification.

The bearer-token authentication helper AshAuthentication.Plug.Helpers.retrieve_from_bearer/3 verifies an Authorization: Bearer JWT's signature and rejects tokens containing an act claim, but performs no check that the token's purpose claim equals user at the bearer boundary. When the resource i

