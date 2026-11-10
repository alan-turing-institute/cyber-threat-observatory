# Daily identity and access threats

- **Report date:** 2026-11-09
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-123551

**PIR:** 1.b · **CVSS:** 10.0

OpenAM from 14.0.0 before 16.1.4 contains an information disclosure vulnerability that allows unauthenticated attackers to read live session tokens from the notification WebSocket. Attackers can bypass the agent-only check through an unvalidated internal forward on legacy Liberty ID-FF endpoints, collecting iPlanetDirectoryPro tokens to hijack user and administrator sessions.

## CVE-2026-123550

**PIR:** 1.b · **CVSS:** 9.8

OpenAM before 16.1.4 contains an authentication bypass vulnerability in its SAML v2.0 service provider that accepts unsigned assertions on the ECP (PAOS) and HTTP-Artifact bindings when WantAssertionsSigned is false. Unauthenticated remote attackers can submit forged assertions to obtain sessions as any mapped user, including administrators, and hijack single sign-on to dependent applications.

## CVE-2026-123549

**PIR:** 1.b · **CVSS:** 9.8

OpenAM before 16.1.4 fails to enforce the Valid Creation Attributes list during self-registration, allowing anonymous attackers to set restricted attributes including group membership. Attackers can register through the legacy self-service REST endpoint or User Self-Service flow to join administrative groups and gain full administrative control of OpenAM.

## CVE-2026-8639

**PIR:** 1.b · **CVSS:** 8.8

IBM Security Verify Directory 10.0.0 through 10.0.4 and IBM Verify Directory 11.0.0 is vulnerable to session fixation. An attacker can establish a session and, after the victim authenticates, hijack the authenticated session to gain unauthorized access to the directory management console.

## CVE-2026-123542

**PIR:** 1.b · **CVSS:** 7.6

OpenAM before 16.1.4 fails to enforce PKCE in the OAuth 2.0 device authorization flow, never validating the code verifier when device codes are exchanged for tokens. Attackers who obtain an approved device code from client logs or shared device storage can redeem it for access and ID tokens to impersonate the user.

## CVE-2026-123538

**PIR:** 1.b · **CVSS:** 7.5

OpenAM before 16.1.4 does not verify that a signed SAML 1.x assertion or response was signed by the partner named as its issuer, accepting a signature from any certificate in OpenAM's keystore. An attacker holding such a private key, such as a trusted SAML 1.x partner, can forge assertions claiming another partner's issuer and sign in as that partner's users, including privileged ones.

## CVE-2026-123545

**PIR:** 1.b · **CVSS:** 7.1

OpenAM from 14.5.1 before 16.1.4 contains a cross-site request forgery vulnerability in the OAuth 2.0 device authorization flow that allows attackers to approve device codes when consent is skipped for implied-consent clients. Attackers can start a device authorization and lure a logged-in user to a crafted page, obtaining access and ID tokens to call APIs as that user.

## CVE-2026-123553

**PIR:** 1.b · **CVSS:** 6.9

OpenAM before 16.1.4 ships built-in identities in the Top Level Realm (demo, anonymous, wsc, wsp, SecurityTokenService and agentAuth) with passwords that are identical on every installation, publicly known, and able to authenticate. Unauthenticated remote attackers can log in as these identities to obtain authenticated sessions, and the agent identities can read the configuration of other agent profiles.

## CVE-2026-123544

**PIR:** 1.b · **CVSS:** 6.8

OpenAM before 16.1.4 and its client SDK fail to sufficiently validate responses on the internal server-to-server SOAP channel, allowing network-positioned attackers to affect integrity and availability. Attackers who intercept unencrypted traffic or control a site server can crash receiving processes, tamper with writable files, and possibly execute code.

## CVE-2026-123552

**PIR:** 1.b · **CVSS:** 6.5

OpenAM before 16.1.4 contains a server-side request forgery vulnerability in certificate CRL checking that fetches CRLs from the distribution point named in a presented certificate without restricting the destination or verifying the downloaded CRL's signature. Attackers holding a trusted-CA-chained certificate can make OpenAM request internal hosts, capture configured CRL update credentials, overwrite stored revocation data to block certificate authentication for that CA, and tie up authenticat

## CVE-2026-123546

**PIR:** 1.b · **CVSS:** 6.1

OpenAM before 16.1.4 contains an open redirect and cross-site scripting vulnerability that allows remote attackers to control post-login and logout destinations via the goto and gotoOnFail parameters. Attackers can craft OpenAM login or logout links that redirect victims to phishing sites or run script in the XUI to steal session cookies.

## CVE-2026-121825

**PIR:** 1.b · **CVSS:** 6.1

OpenAM (OpenAM Consortium Edition) 14.0.5 and earlier contains an open redirect vulnerability (CWE-601) in the Liberty ID-FF service provider single sign-on flow. The goto parameter of the /preLogin endpoint is stored as the RelayState of the Liberty ID-FF authentication request without validation, and after the user completes single sign-on at the identity provider, the assertion consumer service redirects the browser to that value. A remote unauthenticated attacker can induce a user to access 

## CVE-2026-123541

**PIR:** 1.b · **CVSS:** 5.3

OpenAM before 16.1.4 contains an open redirect vulnerability that allows remote attackers to redirect users after SAML 1.x single sign-on by exploiting loose trusted-partner destination matching. Attackers can craft links to /SAMLAwareServlet or /SAMLPOSTProfileServlet with a destination host resembling a trusted partner to send authenticated users to attacker-controlled phishing sites.

## CVE-2026-123537

**PIR:** 1.b · **CVSS:** 5.3

OpenAM before 16.1.4 contains a server-side request forgery vulnerability that allows parties registering UMA resource sets to trigger internal requests through unvalidated scope description URLs. Attackers can register resource sets with scope URLs pointing to internal hosts or cloud metadata endpoints, which OpenAM fetches when sending pending-request notification emails, enabling internal network probing.

