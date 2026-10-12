# Daily phishing and identity campaigns

- **Report date:** 2026-10-11
- **Sources:** ketch OSINT (3 queries)

## GhostCode attackers abuse device codes to take over Microsoft 365 accounts

**PIR:** 1.b.2

Threat actors behind the GhostCode campaign are exploiting Microsoft 365 device code authentication flows to bypass multi-factor authentication and seize enterprise accounts. By tricking users into entering legitimate device codes on malicious portals, attackers gain persistent access to email, Teams, and cloud storage. Infrastructure defenders should monitor for anomalous device code sign-ins, enforce conditional access policies, and educate users on recognizing fake authentication prompts.

Source: https://computerworld.com/article/4223889/ghostcode-attackers-abuse-device-codes-to-take-over-microsoft-365-accounts.html

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.c.1

Microsoft security researchers detail a sophisticated phishing operation leveraging generative AI to craft highly convincing device code prompts. The campaign dynamically adapts language and branding to match target organizations, significantly increasing click-through rates. Defenders are advised to deploy AI-aware email filtering, restrict device code usage to trusted networks, and implement continuous authentication monitoring to detect rapid credential validation attempts.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass

**PIR:** 1.b.1

Trend Micro analyzes how the convenience of device code authentication is being weaponized to circumvent traditional MFA controls. Attackers host fake login pages that prompt users to input codes generated on their primary devices, effectively transferring session tokens to malicious infrastructure. IT teams should evaluate the risk-benefit ratio of device code flows, enforce step-up authentication for sensitive actions, and deploy endpoint detection to block unauthorized browser-based auth redi

Source: https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.a.3

Proofpoint examines the tactical shift from traditional credential harvesting to device code exploitation as a primary identity takeover vector. This evolution allows threat actors to bypass passwordless and MFA protections by leveraging legitimate OAuth flows. Security operations centers must update detection rules to flag rapid device code validations, implement zero-trust access controls, and conduct regular identity hygiene audits to mitigate lateral movement risks.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

