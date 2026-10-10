# Daily identity and access threats

- **Report date:** 2026-10-09
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-14502

**PIR:** 1.b · **CVSS:** 9.8

IBM DataPower Gateway 10.5.0.0 through 10.5.0.22, 10.6.1 through 10.6.6, 10.6.0.0 through 10.6.0.10, and 11.0.0.0 through 11.0.0.2 could allow a remote attacker to obtain administrative access due to failure to reject empty passwords during LDAP authentication.

## CVE-2026-107406

**PIR:** 1.b · **CVSS:** 9.5

Memory overflow vulnerability leading to Remote Code Execution or Denial of Service Vulnerability in NetScaler ADC.


NetScaler ADC or NetScaler Gateway must be configured as a SAML SP or SAML IdP, subject to the following version-specific requirements:



 

  *  For the following versions: Applicable only when configured as a SAML IdP:
  *  NetScaler ADC and NetScaler Gateway between 14.1-73.37 and 14.1-73.41, inclusive
  *  NetScaler ADC 14.1-FIPS between 14.1-73.37 FIPS and 14.1-73.41 FIPS, 

## CVE-2026-107640

**PIR:** 1.b · **CVSS:** 9.3

Integrics Enswitch 3.13 through 4.4 contains an authentication bypass vulnerability in /api/json/user/password/update/ that allows unauthenticated attackers to change account passwords by omitting the reset parameter. Attackers can target accounts with no pending reset, whose empty reset_key matches the defaulted empty value, to take over administrator accounts after enumerating valid usernames.

## CVE-2026-108157

**PIR:** 1.b · **CVSS:** 9.2

Pingvin Share X from 0.19.0 before 1.22.0 contains an improper authentication vulnerability that allows remote unauthenticated attackers to take over accounts by abusing automatic OAuth email linking in OAuthService.signUp(). Attackers can register a victim's unverified email on an enabled OAuth/OIDC provider, exploiting the missing email_verified check in GenericOidcProvider, to sign in as the victim including administrators while bypassing TOTP.

## CVE-2026-16823

**PIR:** 1.b · **CVSS:** 9.1

IBM Security Verify Access 10.0 through 10.0.9.2 and IBM Verify Identity Access 11.0 through 11.0.3 could allow a remote attacker to bypass security restrictions due to improper authentication.

## CVE-2026-19491

**PIR:** 1.b · **CVSS:** 9.1

IBM Security Verify Access 10.0 through 10.0.9.2 and IBM Verify Identity Access 11.0 through 11.0.3 could allow a remote attacker to bypass authentication due to improper authentication.

