# Daily phishing and identity campaigns

- **Report date:** 2026-08-08
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.f

Threat actors are leveraging AI to automate device code phishing at scale, generating live authentication prompts on demand. This campaign bypasses traditional MFA by tricking users into authorizing malicious OAuth consent grants. IT defenders should monitor for anomalous consent requests, enforce conditional access policies, and deploy AI-driven detection to identify automated credential harvesting infrastructure.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.g

Recent telemetry reveals a surge in device code phishing attacks targeting enterprise identity providers. Attackers exploit the convenience of QR-based and short-code authentication flows to harvest valid tokens without triggering standard MFA alerts. Infrastructure teams must implement strict OAuth scope restrictions, monitor for rapid sequential consent approvals, and educate users on verifying authorization prompts.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass

**PIR:** 1.e

This analysis details how device code authentication mechanisms are weaponized to circumvent multi-factor authentication. By redirecting users to spoofed consent pages, adversaries obtain long-lived access tokens that persist even after password resets. Defenders should prioritize token lifecycle management, enforce just-in-time access, and deploy identity threat detection platforms to flag suspicious OAuth grant patterns.

Source: https://trendmicro.com/en/research/26/g/device-code-phishing.html

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.g

Device code phishing represents a paradigm shift in identity attacks, rendering traditional MFA controls ineffective. Attackers exploit legitimate authentication endpoints to harvest consent grants, enabling persistent access to cloud environments. IT infrastructure teams must adopt zero-trust identity architectures, restrict device code flows to approved applications, and implement behavioral analytics to detect automated consent harvesting.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j

Identity takeover campaigns are evolving beyond credential stuffing to exploit OAuth device code flows. This report outlines attack chains where adversaries combine social engineering with automated token harvesting to maintain persistent access. Security operations centers should correlate identity logs with network telemetry, enforce strict consent policies, and deploy phishing-resistant MFA alternatives to mitigate token-based compromises.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog

**PIR:** 1.f

This deep dive examines the convergence of illicit consent grants and AI-powered phishing-as-a-service platforms. Attackers now automate the entire device code phishing lifecycle, from victim targeting to token extraction. Infrastructure defenders must audit third-party application permissions, implement continuous consent monitoring, and integrate identity threat intelligence to disrupt AI-driven credential harvesting campaigns.

Source: https://slashid.com/blog/illicit-consent-grant-part-2

