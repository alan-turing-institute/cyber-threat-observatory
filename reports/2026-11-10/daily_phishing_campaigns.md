# Daily phishing and identity campaigns

- **Report date:** 2026-11-10
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing

**PIR:** 1.j.3

EvilTokens represent a critical evolution in identity compromise, where attackers steal long-lived OAuth refresh tokens via device code phishing. These tokens grant persistent, passwordless access to cloud environments, often evading traditional SIEM alerts. Defenders should enforce short token lifespans, implement continuous access evaluation, and deploy identity-specific EDR solutions to detect and revoke malicious token usage across hybrid infrastructure.

Source: https://microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.f

Device code phishing has shifted from simple credential harvesting to full identity takeover by exploiting OAuth 2.0 device authorization flows. Attackers trick users into entering codes on malicious sites, granting them direct access to corporate accounts without passwords. Infrastructure teams must disable unnecessary device code grants, enforce conditional access policies, and monitor for anomalous OAuth token issuance to mitigate this growing threat vector.

Source: https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Device code phishing bypasses password stealing

**PIR:** 1.f

Traditional password phishing is increasingly obsolete as attackers pivot to device code flows that directly harvest OAuth tokens. This technique circumvents password-based MFA and conditional access policies tied to credential validation. Security operations must shift focus to token lifecycle management, implement strict OAuth consent policies, and deploy identity threat detection platforms capable of correlating device code usage with anomalous authentication patterns.

Source: https://reversinglabs.com/blog/device-code-phishing-campaign

## Multi-Hop Google Redirects Phishing Campaign Analysis 2026

**PIR:** 1.b

Threat actors chain Google Meet, DoubleClick, and Custom Search to create multi-hop redirect sequences that bypass security gateways. This campaign dynamically constructs legitimate-looking URLs to evade URL filtering and proxy inspection. Defenders should monitor for unusual Google service chaining, implement strict egress filtering, and deploy AI-driven URL reputation checks to detect these evasion tactics before credential harvesting occurs.

Source: https://aviatrix.ai/threat-research-center/multi-hop-google-redirects-phishing-campaign-2026/

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.g

This campaign leverages generative AI to dynamically generate highly convincing phishing pages and contextual prompts that mimic Microsoft 365 login flows. AI models adapt messaging in real-time based on user interaction, significantly increasing success rates. Defenders should prioritize behavioral analytics over static URL blocking, implement MFA fatigue protections, and train users to recognize AI-crafted social engineering cues targeting device code prompts.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## Crafty Microsoft Teams Booking Flow Disguises Device Code Phishing

**PIR:** 1.f

Attackers abuse Microsoft Teams meeting booking workflows to deliver device code phishing prompts disguised as legitimate calendar invitations. By embedding malicious OAuth authorization requests within trusted Teams UI elements, threat actors bypass user suspicion and security controls. IT teams should audit Teams app permissions, restrict external meeting bookings, and deploy endpoint detection rules to flag unauthorized OAuth consent requests originating from collaboration platforms.

Source: https://huntress.com/blog/crafty-microsoft-teams-booking-flow-disguises-device-code-phishing

## Joint advisory: state-sponsored spear-phishing campaigns targeting critical infrastructure - SUVAT

**PIR:** 1.c

Five Eyes intelligence agencies report coordinated spear-phishing operations by state-sponsored actors targeting energy, transportation, and government sectors. Campaigns utilize highly tailored lures, legitimate document hosting, and RDP file attachments to establish initial access. Infrastructure defenders must prioritize email gateway hardening, disable macro execution by default, and implement network segmentation to limit lateral movement following initial compromise.

Source: https://suvat.uk/blog/five-eyes-advisory.html

## Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files | Microsoft Security Blog

**PIR:** 1.c

The Midnight Blizzard threat group distributes spear-phishing emails containing malicious RDP files designed to bypass email security filters and establish remote access. These files often leverage signed binaries and living-off-the-land techniques to evade endpoint detection. Defenders should block RDP file execution via application control, monitor for unusual PsExec or WMI activity, and enforce strict remote access policies to mitigate this persistent threat.

Source: https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/

