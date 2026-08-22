# Daily identity and access threats

- **Report date:** 2026-08-20
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-69836

**PIR:** 1.b · **CVSS:** 10.0

Deserialization of untrusted data in Microsoft Entra ID allows an unauthorized attacker to execute code over a network.

## CVE-2026-69851

**PIR:** 1.b · **CVSS:** 9.9

Server-side request forgery (ssrf) in Azure Active Directory allows an authorized attacker to elevate privileges over a network.

## CVE-2026-19490

**PIR:** 1.b · **CVSS:** 9.3

Vulnerability in NetScaler ADC and NetScaler Gateway.

This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

## CVE-2026-53424

**PIR:** 1.b · **CVSS:** 9.1

Authentication Bypass by Capture-replay vulnerability in dropbox samly allows an attacker to authenticate as the subject of a captured SAML assertion by resubmitting it.

Samly.Helper.decode_idp_auth_resp/3 in lib/samly/helper.ex calls esaml_sp:validate_assertion/2, whose default duplicate detector is a no-op. The /3 arity accepting a DuplicateFun exists in esaml and implements the check, but Samly never calls it and offers no configuration to supply one, so the SAML 2.0 Web Browser SSO Profile 

## CVE-2026-49283

**PIR:** 1.b · **CVSS:** 8.7

The SimpleSAMLphp SAML2 library is a PHP library for SAML2 related functionality. Prior to versions 4.19.3, 4.20.2, 5.0.6, and 6.2.1, the HTTPArtifact::receive() flow can treat an unsigned embedded SAML Response as cryptographically valid for the wrong identity provider. SOAPClient::addSSLValidator() attaches a TLS-based validator to the outer SOAP ArtifactResponse, while the embedded Response receives a validator that delegates to the outer message and is later checked against metadata selected

