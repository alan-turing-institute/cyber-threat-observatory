# Daily identity and access threats

- **Report date:** 2026-11-17
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-100397

**PIR:** 1.b · **CVSS:** 10.0

Rucio is a scientific data management framework. From 1.14.0 until 35.9.1, 38.6.1, 40.4.2, and 41.1.1, validate_auth_token in lib/rucio/core/authentication.py does not distinguish short-lived SSH challenge nonces from authentication tokens stored in the same token table. An unauthenticated attacker can request /auth/ssh_challenge_token for an arbitrary account by supplying X-Rucio-Account, then present the returned X-Rucio-SSH-Challenge-Token as X-Rucio-Auth-Token to authenticate to other API en

## CVE-2026-129280

**PIR:** 1.b · **CVSS:** 9.3

Multiple ServerUI and ServerUI2 SOAP operations in N-able N-central before 2026.4.1 HF3 do not verify the caller's session, permissions or customer scope. A remote attacker, in some cases without authentication, can read device and patch data, test passwords of user accounts, send messages to managed agents, and modify device and service settings belonging to other customers.

## CVE-2026-129272

**PIR:** 1.b · **CVSS:** 9.3

N-able N-central before 2026.4.1 HF3 uses a predictable credential to authenticate appliances to an agent-facing API. A remote, unauthenticated attacker who knows or guesses an appliance identifier can obtain a valid appliance token and session and impersonate that appliance.

## CVE-2026-110782

**PIR:** 1.b · **CVSS:** 8.7

The SimpleSAMLphp SAML2 library is a PHP library for SAML2 related functionality. From 6.2.2 until 6.2.4 and 7.0.0-rc2, HTTPArtifact::receive() in src/Binding/HTTPArtifact.php verifies a signed outer ArtifactResponse but returns an unsigned embedded SAML Response before calling verifyMessageSignature(). The signed path verifies with the artifact issuer's metadata keys without requiring the embedded Response issuer to match that artifact issuer. In a multi-IdP federation, an attacker controlling 

