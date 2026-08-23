# Daily identity and access threats

- **Report date:** 2026-08-18
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-69836

**PIR:** 1.b · **CVSS:** 10.0

Deserialization of untrusted data in Microsoft Entra ID allows an unauthorized attacker to execute code over a network.

## CVE-2026-69851

**PIR:** 1.b · **CVSS:** 9.9

Server-side request forgery (ssrf) in Azure Active Directory allows an authorized attacker to elevate privileges over a network.

## CVE-2026-74894

**PIR:** 1.b · **CVSS:** 9.8

openssl_encrypt before 1.4.0 contains an authentication bypass vulnerability in the verify_api_token function that accepts any non-empty Bearer token string without validation. Attackers can upload arbitrary public keys, enumerate all keys, and revoke keys belonging to any user by providing any Bearer token in the Authorization header.

## CVE-2026-57580

**PIR:** 1.b · **CVSS:** 9.4

authentik is an open-source identity provider. Prior to 2026.2.6 and 2026.5.5, an inbound SAML Source configured with the non-default USERNAME_LINK or EMAIL_LINK user-matching mode interprets an XML comment in a NameID differently from the identity provider's signed assertion. An attacker with an account on the source identity provider who can set the account's NameID can inject an XML comment that truncates the value used by authentik to the text before the comment while the signed assertion re

## CVE-2026-19490

**PIR:** 1.b · **CVSS:** 9.3

Vulnerability in NetScaler ADC and NetScaler Gateway.

This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

## CVE-2026-18963

**PIR:** 1.b · **CVSS:** 9.1

A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials.

