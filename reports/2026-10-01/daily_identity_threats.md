# Daily identity and access threats

- **Report date:** 2026-10-01
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-76504

**PIR:** 3.k · **CVSS:** 9.8

A vulnerability in the API session-based authentication management of Cisco Catalyst SD-WAN Manager could allow an unauthenticated, remote attacker to access an affected system with privileges of the admin user.

This vulnerability is due to improper handling of URI encoding in an HTTP request, which allows the request to bypass an authentication rule that is intended to restrict access to a specific API endpoint. An attacker could exploit this vulnerability by sending a crafted HTTP request t

## CVE-2026-102115

**PIR:** 1.b · **CVSS:** 9.8

Kiteworks Core did not correctly validate a parameter submitted to the password reset workflow. An unauthenticated attacker who knew the email address of a user with a locally stored password could potentially reset that account's password without access to the emailed reset link and then authenticate as that user, including where the account holds administrative privileges.

## CVE-2026-88920

**PIR:** 1.b · **CVSS:** 9.8

An authentication bypass in the DOM security processor in Apache WSS4J allows unauthenticated remote attackers to forge authenticated SOAP messages via a crafted unsigned SAML sender-vouches assertion containing an attacker-controlled key.

Users are recommended to upgrade to versions 4.0.2 or 3.0.6 or 2.4.4, which fix this issue.

## CVE-2026-97274

**PIR:** 1.b · **CVSS:** 9.8

Unauthenticated Bypass Vulnerability in OAuth Single Sign On – SSO (OAuth Client) <= 7.1.2 versions.

## CVE-2026-102149

**PIR:** 1.b · **CVSS:** 9.4

Kiteworks Email Protection Gateway did not sufficiently restrict which account a certificate could be assigned to. This could allow an attacker to associate a certificate with another user's account, affecting the confidentiality and integrity of that account's encrypted mail and, where certificate-based login is enabled, potentially permitting unauthorized access to the account.

## CVE-2026-76142

**PIR:** 1.b · **CVSS:** 9.3

Insufficient authentication and access control on the internal-only IPC SOAP endpoint of the Genian NAC/ZTNA policy server allows an unauthenticated attacker to invoke internal functions

## CVE-2026-102106

**PIR:** 1.b · **CVSS:** 9.1

Improper authentication in a Kiteworks Email Protection Gateway administrative service. An administrative service in Kiteworks Email Protection Gateway did not consistently enforce administrator authentication, so the required password check could be bypassed. An attacker who referenced a valid administrator account could potentially create, modify, or delete internal users and managed domains and change their security-feature configuration without authenticating; deleting a managed domain also 

## CVE-2026-103651

**PIR:** 1.b · **CVSS:** 7.6

MISP contains a vulnerability in its one-time password (OTP) authentication flow that allows replay of a consumed HOTP (paper) token and rewinding of the token counter.

The HOTP verification logic compared the submitted token against a counter value that was cached in the user's session at the time the password was entered, rather than against the authoritative counter stored in the database. Because the session-cached counter is not updated after a token is successfully consumed, an attacker w

## CVE-2026-102128

**PIR:** 1.b · **CVSS:** 7.5

An identity-verification weakness in Kiteworks Email Protection Gateway allowed the gateway to act on the Kiteworks platform on behalf of a user it had not authenticated, and to provision a platform account for an identity it did not already know. A remote, unauthenticated sender could potentially exploit this to obtain control of a platform account.

