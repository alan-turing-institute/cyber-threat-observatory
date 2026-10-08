# Daily identity and access threats

- **Report date:** 2026-10-07
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-92414

**PIR:** 1.b · **CVSS:** 9.3

: Session Fixation / Session Reuse across Users vulnerability in Apache Jackrabbit.



Jackrabbit WebDAV server attaches a cached authenticated session on any Lock-Token/TransactionId/SubscriptionId/If-header field token match with

no credential check.



This issue affects Apache Jackrabbit: from 2.23.0 through 2.23.5, from 2.22.0 through 2.22.4, from 2.20.0 through 2.20.17.












Users are recommended to upgrade to versions 2.23.6, 2.22.5, or 2.20.18 which fix the issue.

## CVE-2026-76483

**PIR:** 1.b · **CVSS:** 9.1

As part of Cisco's ongoing commitment to proactive security and product quality, the engineering team for Cisco License On-Prem, formerly Cisco Smart Software Manager On-Prem (SSM On-Prem), has conducted a comprehensive internal security review. This review resulted in software hardening releases that address multiple internally discovered vulnerabilities. &nbsp;

The vulnerabilities tracked by CVE-2026-76483 are related to issues with insufficiently protected credentials that are grouped unde

## CVE-2026-106488

**PIR:** 1.b · **CVSS:** 8.1

Backstage is an open framework for building developer portals. Prior to 0.4.20, the @backstage/plugin-auth-backend-module-oidc-provider package is affected by improper authentication in the oidc provider. Deployments using OIDC email-based identity resolution with a provider that permits unverified email addresses may allow an authenticated provider user to assume another catalog identity. This may grant access and permissions associated with that user. No direct availability impact is demonstra

## CVE-2026-83540

**PIR:** 1.b · **CVSS:** 7.7

When password or public key authentication is used with the Windows port of wolfSSHd, the Windows logon token acquired for one authenticated connection is not released before a token is acquired for a subsequent connection, resulting in user login poisoning between connections. A less privileged user with a valid account on the server can exploit this to force a login as a more privileged user. The vulnerability was introduced with the initial Windows port of wolfSSHd in wolfSSH version 1.4.15 a

## CVE-2026-59358

**PIR:** 1.b · **CVSS:** 7.6

Improper authentication (CWE-287) in the OAuth token endpoint in Cloud Foundry UAA allows a remote, authenticated attacker holding a valid user access token to obtain a fully-privileged client_credentials token for the OAuth client that issued it, by presenting the user token as an OAuth 2.0 Bearer credential on a client_credentials grant request in place of the client’s configured secret.



UAA’s client_credentials handling does not verify that the Bearer credential supplied for client authent

## CVE-2026-107162

**PIR:** 1.b · **CVSS:** 7.6

Express Gateway through 1.16.11 contains an authentication bypass vulnerability in the OAuth 2.0 refresh_token grant that fails to validate the token secret or issuing client. Attackers with any valid client credentials and the identifier portion of another user's refresh token can obtain that user's access token and impersonate them against oauth2-protected APIs.

