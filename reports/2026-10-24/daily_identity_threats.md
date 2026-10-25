# Daily identity and access threats

- **Report date:** 2026-10-24
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-115547

**PIR:** 1.b · **CVSS:** 9.1

An input validation issue in the Okta Access Gateway (OAG) Admin Console allows the processing of specially formatted configuration values. An authenticated administrator can leverage this to execute system commands within the context of the OAG service account.

## CVE-2026-79977

**PIR:** 1.b · **CVSS:** 8.2

The WireGuard VPN service in subsys/net/lib/wireguard/wg.c updated the peer endpoint from a message it could not authenticate. In handle_transport_data(), when the 32-bit receiver index of an incoming transport-data message matched no session, the code both scheduled a new handshake and copied the datagram's source address into peer->endpoint with memcpy(&peer->endpoint, peer_addr, sizeof(peer->endpoint)). Because the receiver index is unknown, there is no key with which such a message could be 

## CVE-2026-115546

**PIR:** 1.b · **CVSS:** 8.1

Okta Access Gateway (OAG) does not validate the selected authentication source during sign-on. An authenticated user with an active session can modify the authentication source parameter, which may generate a SAML assertion granting access to the Admin Console.

## CVE-2025-30043

**PIR:** 1.b · **CVSS:** 7.1

CGM CLININET is vulnerable to Missing Authentication for Critical Function in the /DocManagment path. The endpoint is accessible without authentication, allowing an unauthenticated attacker in the adjacent network to retrieve the list of patient documents and download those documents. 


This issue was fixed in version 2026.MS3

## CVE-2025-30053

**PIR:** 1.b · **CVSS:** 6.9

The CGM CLININET application runs the cgm-updater process listening on an open network port without any authentication.




The vulnerability was confirmed to affect versions up to 2026.MS3 but later versions may also be vulnerable.

