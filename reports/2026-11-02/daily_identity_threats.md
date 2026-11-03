# Daily identity and access threats

- **Report date:** 2026-11-02
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-105769

**PIR:** 1.b · **CVSS:** 9.3

kaniko before 1.25.20 can send a Microsoft Entra ID (Azure AD) access token for Azure Resource Manager to an attacker-controlled registry host. kaniko uses the Azure Container Registry credential helper github.com/chrismellard/docker-credential-acr-env, which decides whether a host is an ACR registry with an unanchored regular expression, so any hostname containing .azurecr.io, .azurecr.cn, .azurecr.de or .azurecr.us is accepted. kaniko consults this helper for any registry that has no credentia

## CVE-2026-116606

**PIR:** 1.b · **CVSS:** 9.3

An authentication bypass in Barracuda Email Security Gateway versions earlier than 9.4.0.030 allows an unauthenticated remote attacker to invoke a configuration-import function and restore a crafted, compatible backup archive, resulting in unauthorized modification of the appliance’s global configuration.

## CVE-2026-88810

**PIR:** 1.b · **CVSS:** 7.2

A privilege escalation issue was discovered in Rancher Manager's role-based access control. The inheritedNamespacedRules field of a GlobalRole propagates permissions into named namespaces of every downstream cluster managed by the Rancher instance, but it was not subject to the privilege-escalation validation applied to the other permission-carrying fields of a GlobalRole. As a result, a non-administrative user could be granted, through a global role  binding, permissions in downstream clusters 

## CVE-2026-82840

**PIR:** 1.b · **CVSS:** 7.2

Session fixation in Apache Wicket.

org.apache.wicket.authroles.authentication.AuthenticatedWebSession is the authentication base class of Wicket's role-based security module, and its signIn(String, String) method is the entry point through which an application authenticates a session. Renewing the container session id at that point is the standard defence against an attacker who has fixed a session id in a victim's browser, and Wicket provides that renewal as org.apache.wicket.Session#changeSes

## CVE-2024-9517

**PIR:** 1.b · **CVSS:** 4.9

The refresh token grant type in WSO2 products fails to re-validate account status before issuing new access tokens. This weakness allows an attacker to obtain valid access tokens for user accounts even after they have been blocked by the user store, bypassing account lockout mechanisms.

This vulnerability can lead to unauthorized access to user accounts and their associated resources. Attackers can leverage this to perform actions on behalf of blocked users, potentially leading to privilege esc

## CVE-2026-120263

**PIR:** 1.b · **CVSS:** 0.0

When `[oauth2_client].ACCOUNT_LINKING` is set to `auto` (not the default) and registration is enabled, the link-account sign-up form looked up the existing account to link by the user name or email submitted in the form instead of the identity asserted by the OAuth2 provider. An attacker with an account on a configured OAuth2 provider could submit another user's name, link their external identity to that Gitea account and be signed in as it without its password, including as an administrator. Th

