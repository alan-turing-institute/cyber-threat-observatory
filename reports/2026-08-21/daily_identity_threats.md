# Daily identity and access threats

- **Report date:** 2026-08-21
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-69836

**PIR:** 1.b · **CVSS:** 10.0

Deserialization of untrusted data in Microsoft Entra ID allows an unauthorized attacker to execute code over a network.

## CVE-2026-69851

**PIR:** 1.b · **CVSS:** 9.9

Server-side request forgery (ssrf) in Azure Active Directory allows an authorized attacker to elevate privileges over a network.

## CVE-2026-53424

**PIR:** 1.b · **CVSS:** 9.1

Authentication Bypass by Capture-replay vulnerability in dropbox samly allows an attacker to authenticate as the subject of a captured SAML assertion by resubmitting it.

Samly.Helper.decode_idp_auth_resp/3 in lib/samly/helper.ex calls esaml_sp:validate_assertion/2, whose default duplicate detector is a no-op. The /3 arity accepting a DuplicateFun exists in esaml and implements the check, but Samly never calls it and offers no configuration to supply one, so the SAML 2.0 Web Browser SSO Profile 

## CVE-2026-76633

**PIR:** 1.b · **CVSS:** 8.6

WeGIA before 3.9.2 contains an authorization bypass vulnerability in the password change flow that allows any authenticated user to change their account password without providing existing credentials by exploiting the unconditional exclusion of the alterarSenha method from permission checks in controle/control.php. Attackers can manipulate the redir parameter to point to alterar_senha.php, routing through verificarSenhaConfig() instead of verificarSenha() to bypass current password verification

## CVE-2026-53425

**PIR:** 1.b · **CVSS:** 7.6

Insufficient Verification of Data Authenticity vulnerability in dropbox samly allows an attacker to establish an authenticated session using a SAML response the service provider never requested.

Samly.SPHandler.validate_authresp/3 in lib/samly/sp_handler.ex validates a SAML response for the SP-initiated flow by comparing only the RelayState value, the IdP identifier, and the presence of a target URL held in the session. It never compares SubjectConfirmationData/@InResponseTo against the ID of t

## CVE-2026-54789

**PIR:** 1.b · **CVSS:** 7.5

mod_auth_openidc is an OpenID Certified authentication and authorization module for the Apache 2.x HTTP server that implements the OpenID Connect Relying Party functionality. Prior to 2.4.19.4, an out-of-bounds read and a one-byte out-of-bounds write exist in the state-cookie parser of `mod_auth_openidc`. The issue is fixed in version 2.4.19.4 by stopping the scan at the string terminator so a value-less token is rejected. No in-product workarounds are available. As a stop-gap, an upstream rever

## CVE-2026-49217

**PIR:** 1.b · **CVSS:** 7.5

Mailu is a mail server as a set of Docker images. Prior to version 2024.06.52, a missing authorization check in the Mailu admin REST API allows any unauthenticated attacker to remove any potential IP restriction or update the comment field from any existing user token provided the REST API is enabled. Upgrade to Mailu 2024.06.52 to receive a patch or, as a workaround, turn the REST API off.

## CVE-2026-19611

**PIR:** 1.b · **CVSS:** 7.4

A flaw was found in WildFly Elytron. Password hashing and verification normalize input with Unicode NFKC, which can collapse fullwidth characters to ASCII equivalents. A remote attacker can more easily guess affected passwords by using an ASCII-only dictionary against accounts whose passwords were intended to include those non-ASCII characters, leading to unauthorized access.

