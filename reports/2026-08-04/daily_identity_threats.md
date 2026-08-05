# Daily identity and access threats

- **Report date:** 2026-08-04
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-18108

**PIR:** 1.b · **CVSS:** 9.8

Net::SAML2 versions before 0.86 for Perl allow authentication bypass because _verify_encrypted_assertion accepts an EncryptedAssertion whose decrypted content carries no signature.

_verify_encrypted_assertion decrypts the EncryptedAssertion and returns it as verified when it carries no signature, via "return $xml unless $xpath->exists('dsig:Signature', $assert);". The signature check and the trust anchor check that follow run only when a signature is present, so a decrypted assertion with no ds

## CVE-2026-67610

**PIR:** 1.b · **CVSS:** 8.6

OpenEMR through 8.2.0 contains an improper authentication vulnerability in the OAuth2 dynamic client registration endpoint that allows unauthenticated attackers to register a malicious client with system-level FHIR scopes by supplying a self-generated RSA keypair via the jwks field. Once an administrator approves the registered client, attackers can use the client_credentials grant with a self-signed JWT assertion to obtain access tokens granting read access to all FHIR resources across all pati

## CVE-2026-18092

**PIR:** 1.b · **CVSS:** 8.1

Net::SAML2 versions before 0.86 for Perl allow SAML authentication bypass via XML signature wrapping because new_from_xml reads assertion identity with document-wide XPath instead of the signed subtree.

new_from_xml reads the NameID, attribute values, SessionIndex, audience and other identity fields with document-wide XPath, such as //saml:Assertion/saml:AttributeStatement/saml:Attribute and //saml:Subject/saml:NameID, which select the first matching element in document order rather than the el

## CVE-2026-18089

**PIR:** 1.b · **CVSS:** 7.5

Net::SAML2 versions before 0.86 for Perl allow SAML authentication bypass by verifying responses against the response-embedded certificate in verify_xml when no trust anchor is configured.

verify_xml in Net::SAML2::Role::VerifyXML runs "return if !$anchors && !$cacert;" as soon as the XML::Sig check succeeds, and that check uses the X.509 certificate taken from the response's own dsig:KeyInfo/dsig:X509Certificate element, so an unanchored response is checked only against the key it carries. Bin

## CVE-2026-18651

**PIR:** 1.b · **CVSS:** 5.4

A flaw was found in 389 Directory Server. During SASL PLAIN authentication, the server installs connection-level bind credentials before performing the account-lock check. If the account is subsequently found to be locked, the bind is reported as failed to the client, but the already-installed authenticated state on the connection is not reverted. A client that supplies valid credentials for an account that has been administratively locked can continue to use the same connection with that accoun

## CVE-2026-18569

**PIR:** 1.b · **CVSS:** 3.7

A flaw was found in the backchannel logout endpoint of the keycloak-services component, which is part of the Red Hat Build of Keycloak. This component handles authentication and session management for applications. The issue occurs when an OIDC identity provider is configured to skip signature validation. In this specific setup, the system incorrectly accepts logout requests that have no cryptographic signature. An attacker who knows certain technical details about a user's session can use this 

