# Daily identity and access threats

- **Report date:** 2026-11-03
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-118527

**PIR:** 3.k · **CVSS:** 4.3

Use of predictable filenames in Ivanti Connect Secure before versions 25.1.1.3 and 22.8R2.6 allows a remote authenticated attacker to upload files with attacker-controlled content to a known location on disk.

## CVE-2026-105769

**PIR:** 1.b · **CVSS:** 9.3

kaniko before 1.25.20 can send a Microsoft Entra ID (Azure AD) access token for Azure Resource Manager to an attacker-controlled registry host. kaniko uses the Azure Container Registry credential helper github.com/chrismellard/docker-credential-acr-env, which decides whether a host is an ACR registry with an unanchored regular expression, so any hostname containing .azurecr.io, .azurecr.cn, .azurecr.de or .azurecr.us is accepted. kaniko consults this helper for any registry that has no credentia

## CVE-2026-116606

**PIR:** 1.b · **CVSS:** 9.3

An authentication bypass in Barracuda Email Security Gateway versions earlier than 9.4.0.030 allows an unauthenticated remote attacker to invoke a configuration-import function and restore a crafted, compatible backup archive, resulting in unauthorized modification of the appliance’s global configuration.

## CVE-2026-121736

**PIR:** 1.b · **CVSS:** 6.9

NocoDB 0.300.0 before 2026.08.0 contains a missing authentication vulnerability in the POST /api/v2/oauth/authorize handler that allows unauthenticated attackers to create OAuth authorization codes. Attackers can send anonymous requests with client_id, redirect_uri and approved=true to insert unbounded ownerless authorization code records, limited only by rate limiting.

## CVE-2026-121454

**PIR:** 1.b · **CVSS:** 6.3

Padloc through 4.3.0 contains a missing authentication vulnerability in ScimServer._handleScimGet() that allows unauthenticated attackers to read SCIM directories by sending any non-empty bearer token. Attackers who know an organization id can query the Users and Groups SCIM endpoints to retrieve provisioned usernames, emails, names, externalIds, and group memberships.

