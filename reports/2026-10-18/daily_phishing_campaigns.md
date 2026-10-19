# Daily phishing and identity campaigns

- **Report date:** 2026-10-18
- **Sources:** ketch OSINT (3 queries)

## Microsoft Disrupts YAM Store Network Behind 1 Billion Phishing Scams and M365 Device-Code Attacks

**PIR:** 1.e

Microsoft’s security operations dismantled the YAM Store network, a massive infrastructure facilitating over one billion phishing attempts and widespread Microsoft 365 device-code attacks. The campaign leveraged compromised legitimate domains and cloud-hosted landing pages to bypass traditional email filters. Infrastructure defenders should monitor for anomalous OAuth consent grants, enforce conditional access policies restricting device-code flows, and implement DNS sinkholing for known malicio

Source: https://windowsforum.com/news/microsoft-disrupts-yam-store-network-behind-1-billion-phishing-scams-and-m365-device-code-attacks.448313/post-1012947

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.f

This analysis maps the underground infrastructure ecosystem enabling global phishing campaigns, detailing how threat actors rent cloud instances, abuse CDN networks, and rotate domains to evade takedowns. Defenders can leverage the disclosed infrastructure indicators to enhance proxy filtering, block malicious ASN ranges, and deploy machine learning models for domain age and hosting pattern analysis. Understanding these supply-chain tactics is critical for hardening network egress controls and p

Source: https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass

**PIR:** 1.e

Trend Micro details how attackers exploit Microsoft’s device-code authentication flow to circumvent multi-factor authentication. By hosting malicious portals that prompt users to enter device codes, threat actors hijack active sessions without capturing passwords or MFA tokens. Infrastructure teams must disable unnecessary device-code grants via Azure AD conditional access, monitor for high-frequency consent requests, and educate users on recognizing legitimate device-code prompts. This techniqu

Source: https://www.trendmicro.com/en_us/research/26/g/device-code-phishing.html

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.f

CYFIRMA researchers document how modern phishing operations increasingly leverage cloud-native services like serverless functions, object storage, and managed databases to host malicious payloads and phishing pages. This approach reduces infrastructure costs, improves uptime, and complicates traditional blocklisting. Defenders should implement cloud security posture management tools, audit third-party cloud resource usage, and deploy web application firewalls tuned to detect cloud-hosted phishin

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.g

Microsoft Security researchers dissect a campaign utilizing generative AI to dynamically generate phishing pages and automate device-code harvesting at scale. The AI models adapt landing page content in real-time based on victim interaction, increasing conversion rates. Defenders should deploy AI-driven threat detection for behavioral anomalies, restrict OAuth app permissions, and implement user training focused on AI-generated social engineering cues. This marks a shift toward adaptive, automat

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM

**PIR:** 1.a

Threat actors are conducting sophisticated social engineering campaigns within Microsoft Teams, impersonating IT helpdesk personnel to trick employees into sharing credentials, enabling screen sharing, or installing remote monitoring tools. The attacks combine external chat exploitation, vishing, and RMM abuse to bypass email security controls. Infrastructure defenders should enforce Teams external messaging restrictions, monitor for unusual RMM installation patterns, and implement just-in-time 

Source: https://intel.threadlinqs.com/threat/TL-2026-3778

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.f

BreakGlass Intelligence reveals how the SideWinder APT group abuses Platform-as-a-Service environments to host credential harvesting portals at scale. By leveraging legitimate PaaS providers, attackers bypass traditional infrastructure blocklists and maintain persistent access to stolen credentials. Infrastructure teams must monitor for anomalous PaaS resource provisioning, enforce strict identity governance for cloud platforms, and integrate threat intelligence feeds tracking PaaS abuse pattern

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## n8n Weaponized for Phishing and Device Fingerprinting

**PIR:** 1.g

CSA Labs reports on threat actors repurposing the open-source workflow automation tool n8n to orchestrate phishing campaigns and collect device fingerprints. Attackers deploy self-hosted n8n instances to automate email delivery, track victim interactions, and exfiltrate browser telemetry. Defenders should audit internal workflow automation deployments, restrict outbound API calls from automation servers, and monitor for unauthorized n8n instances in cloud environments. This highlights the risk o

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-n8n-ai-workflow-phishing-20260416-csa-styl

