# Daily identity and access threats

- **Report date:** 2026-09-02
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-19117

**PIR:** 1.b · **CVSS:** 9.8

Under specific conditions, an attacker can register an attacker-controlled FIDO2 credential against a target account and then authenticate as
that user. This issue affects on-premises deployments only.

## CVE-2026-84699

**PIR:** 1.b · **CVSS:** 9.3

Team Password Manager before 14.184.308 fails to enforce authentication requirements in the local account password reset flow. Unauthenticated attackers can reset local account passwords and authenticate as those users to gain unauthorized access.

## CVE-2026-84668

**PIR:** 1.b · **CVSS:** 8.8

Jenkins SAML Plugin 4.618.v441a_27fa_46d2 and earlier allows overwriting the SAML identity provider metadata file through Stapler data binding, allowing attackers to replace it with attacker-controlled content and authenticate as any user.

## CVE-2026-84672

**PIR:** 1.b · **CVSS:** 8.8

Jenkins Microsoft Entra ID (previously Azure AD) Plugin 710.v0b_ff8e9cc2d2 and earlier grants Entra group permissions using both the group's unique object ID and its display name, allowing attackers who can create an Entra group with a colliding display name to gain the permissions configured for a privileged group.

## CVE-2026-84423

**PIR:** 1.b · **CVSS:** 7.3

A vulnerability has been found in Casdoor up to 4.0.0. This affects an unknown function of the file controllers/resource.go of the component upload-resource API. Such manipulation leads to missing authentication. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The vendor deleted the GitHub issue for this vulnerability without any explanation. Afterwards the vendor was contacted early about this disclosure via email but did not respond i

## CVE-2026-75136

**PIR:** 1.b · **CVSS:** 6.9

UpSignOn for Windows before 7.19.0 contains an insecure credential storage vulnerability that allows local attackers to retrieve the biometric unlock key stored in the Windows PasswordVault API without triggering any authentication prompt. Attackers can access the stored biometric key from a standard local process within the same Windows session to decrypt the protected vault files and export the entire password manager contents in cleartext.

## CVE-2026-82968

**PIR:** 1.b · **CVSS:** 6.4

A flaw was found in the first-broker-login flow of the Keycloak identity management service. When a user links a social identity provider account to their local account, the verification proof generated is not strictly bound to the specific upstream identity being verified. This allows an attacker with a different account on the same social provider to intercept the process and link their own account to the victim's local profile, gaining unauthorized access.

## CVE-2026-84114

**PIR:** 1.b · **CVSS:** 6.3

A vulnerability has been found in Cleo Harmony up to 5.8.1.10. Impacted is the function LocalUserUtil.getNativeUserByAssertions of the component SAML Authentication. Such manipulation of the argument Email leads to improper authentication. The attack can be executed remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 5.8.1.11 is recommended to address this issue. Upgrading the affected component is recommended.

