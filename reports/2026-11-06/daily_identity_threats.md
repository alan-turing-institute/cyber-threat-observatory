# Daily identity and access threats

- **Report date:** 2026-11-06
- **Source:** DuckDB cve_enriched (identity software / auth CWEs / wild-exploited)

## CVE-2026-117691

**PIR:** 1.b · **CVSS:** 9.1

A flaw was found in the SAML HTTP-Redirect binding implementation of Keycloak. The issue occurs because the server processes percent-encoded parameter names (like %53AMLResponse) while the signature verification logic only checks literal parameter names. An attacker can use this discrepancy to provide a crafted, unsigned SAML message that the server processes instead of a legitimately signed one, leading to full account takeover of federated users.

## CVE-2026-97175

**PIR:** 1.b · **CVSS:** 8.8

A flaw was found in the idp-auto-link authenticator of the keycloak-services component, which handles user identity federation. The issue occurs when Keycloak automatically links an incoming identity from an external provider to an existing local account based on an email address without verifying if the provider has validated that email. This can allow an attacker to take over a victim's account by using a matching unverified email address at a brokered provider.

## CVE-2026-123196

**PIR:** 1.b · **CVSS:** 8.6

Authorizer before 2.4.2 contains a password reset poisoning vulnerability that allows unauthenticated attackers to control emailed link hosts by supplying x-authorizer-url gRPC metadata. Attackers can send this metadata to the gRPC port or a Grpc-Metadata-X-Authorizer-Url header through the REST gateway to capture reset or magic-link tokens and take over accounts.

## CVE-2026-49272

**PIR:** 1.b · **CVSS:** 8.5

OAuthLib is an implementation of the OAuth request-signing logic for Python 3.6+. From 3.3.0 until 4.0.1, OAuthLib's RFC 8628 device workflow does not require DeviceCodeGrant.validate_token_request to check that the device_code parameter is present and valid. A caller whose client request is accepted by the configured validator and who knows a valid client ID enabled for the device workflow can submit a missing or bogus device code to the token endpoint and obtain a bearer token without completi

## CVE-2026-112208

**PIR:** 1.b · **CVSS:** 8.1

A flaw was found in the Organization identity-first login flow of the Keycloak authentication server. Keycloak is an open-source identity and access management solution used to secure modern applications and services. The issue occurs when an attacker who belongs to multiple organizations initiates a login and then switches to a registration or password reset path. During this process, a flag indicating a successful login is not properly cleared when the user is removed from the session. An atta

## CVE-2026-114232

**PIR:** 1.b · **CVSS:** 8.1

A flaw was found in the UserManagedPermissionService of the Keycloak authorization server. The UMA Protection API, which manages user permissions, fails to validate the resourceType field when a user creates a new policy. This allows an attacker to create a policy that applies to resources owned by other users, potentially leading to unauthorized access or modification of sensitive data across the entire realm.

## CVE-2026-92857

**PIR:** 1.b · **CVSS:** 8.1

Keycloak provides a Dynamic Client Registration feature that allows users with specific tokens to register their own applications. A flaw in how Keycloak validates these registration requests allows an attacker to create a malicious application that forges identity information. By mapping their own user profile details to protected fields like the user ID (sub) or intended audience (aud), an attacker can generate signed security tokens that make them appear to be a different user. This could all

## CVE-2026-96453

**PIR:** 1.b · **CVSS:** 8.0

A flaw was found in the Keycloak Admin CLI kcadm tool, which is used by administrators to manage Keycloak servers from the command line. When a custom truststore is provided to verify the server identity, the tool incorrectly accepts any self-signed certificate as long as the hostname matches. This allows a network attacker to impersonate the Keycloak server, steal administrative credentials, and perform unauthorized management actions.

## CVE-2026-123047

**PIR:** 1.b · **CVSS:** 7.5

In Eclipse BaSyx Helm Charts versions 3.0.0-rc.1 to 3.12.1 of the `basyx` chart, deployments with the bundled Keycloak enabled store the passwords of the Keycloak users that the chart creates in cleartext in a Kubernetes ConfigMap.



The template `keycloak-init-config.yaml` rendered `keycloak.initialization.users`, including each user's `credentials[].value`, as `users.json` into the persistent ConfigMap `<release>-basyx-keycloak-init-config`. By default this includes the bootstrap administrato

## CVE-2026-103112

**PIR:** 1.b · **CVSS:** 7.5

A flaw was found in the authentication session handling of the keycloak-services component in Keycloak. The issue occurs because the system fails to verify if an authenticator is valid for the current authentication flow when switching between the standard authentication path and the reset credentials path. An authenticated attacker can exploit this by triggering a race condition during the credential reset process to associate their successful authentication state with another user's session. T

## CVE-2026-123059

**PIR:** 1.b · **CVSS:** 7.5

In Eclipse BaSyx Helm Charts version 2.2.0 of the `aas-basyx-v2-full` chart, deployments with the bundled Keycloak enabled store the client secret of the `basyx-technical-user` OAuth2 client in cleartext in a Kubernetes ConfigMap. This client uses the client-credentials grant and its service account holds the realm `admin` role.



The chart correctly writes `keycloak.technicalUser.clientSecret` to a Kubernetes Secret, but the template `basyx-keycloak-realm.yaml` also substitutes the same value 

