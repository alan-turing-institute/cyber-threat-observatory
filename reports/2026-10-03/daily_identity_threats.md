# Daily identity and access threats

- **Report date:** 2026-10-03
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-105115

**PIR:** 1.b · **CVSS:** 8.8

OpenAM before 16.1.3 contains an unauthenticated arbitrary class instantiation vulnerability in the legacy JAX-RPC SOAP interface that allows remote attackers to load classes without authentication. Attackers can send SOAP requests to /jaxrpc/* with an unverified session identifier and a chosen class name, crashing the server, probing the classpath, or potentially reaching code execution via gadget chains.

## CVE-2026-88779

**PIR:** 1.b · **CVSS:** 8.7

Vulnerability in NetScaler ADC and NetScaler Gateway.

This issue affects ADC: before 14.1-73.41, before 13.1-64.28, before 14.1-73.41 FIPS, and before 13.1-37.282; Gateway: before 14.1-73.41 and before 13.1-64.28.

## CVE-2026-105119

**PIR:** 1.b · **CVSS:** 7.6

OpenAM before 16.1.3 applies its OAuth2 Provider PKCE enforcement only to authorization requests whose response_type is exactly code, so codes issued through OpenID Connect hybrid flows (code token, code id_token, code token id_token) carry no bound challenge. An attacker who intercepts such a code can redeem it for a public client's tokens with any non-empty code_verifier.

## CVE-2026-105120

**PIR:** 1.b · **CVSS:** 6.9

OpenAM before 16.1.3 contains an authorization bypass vulnerability in the sessions REST endpoint query operation that allows realm administrators to list sessions of every realm. Attackers holding delegated RealmAdmin privileges can supply a _queryFilter naming another realm to disclose usernames, universal IDs, and session handles across tenant boundaries.

## CVE-2026-105121

**PIR:** 1.b · **CVSS:** 6.9

OpenAM before 16.1.3 contains an improper authorization vulnerability that allows delegated administrators to destroy sessions outside their realms because realm checks use the requester's realm. Authenticated accounts holding the iplanet-am-session-destroy-sessions attribute can supply a target session identifier or handle to forcibly log out users in any realm.

## CVE-2026-105116

**PIR:** 1.b · **CVSS:** 6.1

OpenAM before 16.1.3 contains a latent cross-site scripting defect that places the SAML message, relay state and target URL unencoded into the load-balancer cookie bounce auto-submit page. If reachable with cookieHashRedirectEnabled set, crafted requests could execute script in the OpenAM origin, though an unrelated HTTP 500 failure prevents exploitation in released versions.

## CVE-2026-105114

**PIR:** 1.b · **CVSS:** 6.1

OpenAM before 16.1.3 contains a reflected cross-site scripting vulnerability that allows unauthenticated attackers to inject script by supplying crafted parameters rendered unencoded on the OAuth2 authorization error page. Attackers can lure victims to a crafted /oauth2/authorize link with repeated parameters to run JavaScript in the OpenAM origin, acting within existing sessions or redirecting to phishing pages.

## CVE-2026-105117

**PIR:** 1.b · **CVSS:** 6.1

OpenAM before 16.1.3 contains an email content injection vulnerability that allows unauthenticated attackers to control notification email wording via the forgotPassword and register actions on /json/{realm}/users. Attackers can supply subject and message fields to send phishing mail from the organisation's configured From address, or abuse register as a relay to arbitrary recipients.

## CVE-2026-105122

**PIR:** 1.b · **CVSS:** 5.4

OpenAM before 16.1.3 contains a server-side request forgery vulnerability that allows attackers able to register or modify OAuth 2.0 clients to make OpenAM fetch internal resources via an unvalidated jwks_uri. Attackers can trigger unauthenticated fetches through client-authentication and ID-token validation to probe internal hosts, metadata endpoints or local files, or exhaust request threads for denial of service.

## CVE-2026-104638

**PIR:** 1.b · **CVSS:** 5.3

A security vulnerability has been detected in onetwothreeneth HospitalManagementSystem up to 9ef91ed6007314b6473110ed699dff76d158f61d. The impacted element is an unknown function of the file php/sessions.php. The manipulation of the argument ID leads to improper authentication. Remote exploitation of the attack is possible. The exploit has been disclosed publicly and may be used. This product follows a rolling release approach for continuous delivery, so version details for affected or updated r

## CVE-2026-105118

**PIR:** 1.b · **CVSS:** 4.7

OpenAM before 16.1.3 contains an open redirect vulnerability that allows unauthenticated attackers to redirect users by supplying an unverified id_token_hint to the /oauth2/connect/endSession endpoint. Attackers can name any realm client in a forged hint to redirect victims to any registered post-logout URI, enabling phishing that borrows the OpenAM host's trust.

## CVE-2026-103877

**PIR:** 1.b · **CVSS:** 0.0

Deserialization of Untrusted Data vulnerability in Apache Directory LDAP API.



A rogue/compromised LDAP server (or pre-TLS MITM) can answer a client's loadSchema() subschema search with a schema object that contains a serialized Java class, allowing some potential RCE. 



This issue affects Apache Directory LDAP API: from 2.1.0 before 2.1.9.



Users are recommended to upgrade to version 2.1.9, which fixes the issue.

