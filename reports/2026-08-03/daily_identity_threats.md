# Daily identity and access threats

- **Report date:** 2026-08-03
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

## CVE-2026-18571

**PIR:** 1.b · **CVSS:** 6.6

A flaw was found in the user creation component of Keycloak when Fine-Grained Admin Permissions V2 (FGAP V2) is enabled. This issue allows a sub-administrator with permission to create users to add those users to any group, even groups the sub-administrator is not authorized to manage. This could lead to unauthorized access to sensitive information or elevated privileges for the newly created users.

## CVE-2026-18573

**PIR:** 1.b · **CVSS:** 6.5

A flaw was found in the keycloak-services component of Keycloak, which is used for managing authentication and authorization flows. The issue occurs when a realm administrator configures client policies to enforce specific authentication requirements on confidential clients. Due to improper evaluation of the client state during an update operation, an attacker with client management permissions can bypass these security policies by first creating a public client and then updating it to a confide

## CVE-2026-18572

**PIR:** 1.b · **CVSS:** 6.5

Keycloak provides authorization services that allow administrators to restrict access to resources based on time policies (for example, only allowing access during business hours). A flaw was discovered where a user can include a fake time value in their authorization request that overrides the actual server time. This allows the user to bypass these time-based restrictions and access protected resources at unauthorized times.

## CVE-2026-18570

**PIR:** 1.b · **CVSS:** 5.4

A flaw was found in the full-scope-disabled client-policy executor within the keycloak-services component. This component is responsible for enforcing security policies during client registration and configuration in Red Hat Build of Keycloak. The issue occurs because the executor only validates the fullScopeAllowed field when it is explicitly provided in a request. By omitting this field, a delegated user can bypass the policy, resulting in a client created with full scope access. This allows t

## CVE-2026-18651

**PIR:** 1.b · **CVSS:** 5.4

A flaw was found in 389 Directory Server. During SASL PLAIN authentication, the server installs connection-level bind credentials before performing the account-lock check. If the account is subsequently found to be locked, the bind is reported as failed to the client, but the already-installed authenticated state on the connection is not reverted. A client that supplies valid credentials for an account that has been administratively locked can continue to use the same connection with that accoun

