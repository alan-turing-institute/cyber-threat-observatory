# Daily phishing and identity campaigns

- **Report date:** 2026-10-23
- **Sources:** ketch OSINT (3 queries)

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.h

Device code phishing has emerged as a primary vector for identity takeover, exploiting OAuth 2.0 device authorization flows to bypass traditional MFA. Threat actors deploy automated toolkits and phishing-as-a-service platforms to harvest valid tokens directly from legitimate authentication endpoints. Infrastructure defenders must monitor for anomalous device code requests, implement conditional access policies, and restrict device flow usage to approved applications.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.e

This Microsoft analysis reveals how AI-driven automation scales device code phishing by generating live authentication codes on demand and maintaining persistent post-compromise access. The campaign demonstrates end-to-end workflow automation that adapts to victim behavior and evades static detection rules. Defenders should deploy behavioral analytics for identity access patterns, restrict AI-assisted automation in authentication flows, and enforce token lifetime limits.

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.g

Threat actors increasingly leverage cloud-native services and serverless architectures to host phishing infrastructure, evading traditional perimeter defenses. This report details how attackers abuse legitimate cloud providers to deploy dynamic phishing pages, rotate domains rapidly, and maintain persistent access. Infrastructure defenders must implement cloud workload protection, monitor for anomalous API usage, and enforce strict egress controls to disrupt these campaigns.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Storm-2372 conducts device code phishing campaign

**PIR:** 1.j.3

The Storm-2372 APT group has conducted a sustained device code phishing campaign since August 2024, mimicking messaging platforms like WhatsApp, Signal, and Teams to harvest credentials. Their infrastructure leverages compromised legitimate domains and dynamic content rendering to evade URL filtering. Infrastructure teams must implement deep packet inspection for OAuth token exchanges, monitor for APT-associated infrastructure, and enforce strict conditional access rules.

Source: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/

## Microsoft Teams Phishing via Fake IT Helpdesk Impersonation (External Chat, Vishing, Screen Sharing, RMM

**PIR:** 1.a

Attackers are impersonating IT helpdesk personnel within Microsoft Teams to conduct targeted phishing, vishing, and unauthorized remote access via screen sharing and RMM tools. By exploiting trust in internal support channels, threat actors bypass email filters and extract credentials or deploy malware. Defenders should enforce strict external chat policies, require multi-factor authentication for RMM access, and train staff to verify helpdesk requests through out-of-band channels.

Source: https://intel.threadlinqs.com/threat/TL-2026-3778

## ShinyHunters Cluster A Phishing Infrastructure on Mevspace (Doko's Panel, vishing + AiTM credential capture)

**PIR:** 1.i

The ShinyHunters cluster operates a sophisticated phishing-as-a-service ecosystem hosted on Mevspace, utilizing Doko's Panel for rapid campaign deployment. This infrastructure supports vishing operations and advanced AI-powered man-in-the-middle credential capture. Infrastructure teams must block known PhaaS domains, implement DNS sinkholing for suspicious TLDs, and deploy real-time threat intelligence feeds to disrupt shared criminal infrastructure.

Source: https://intel.threadlinqs.com/threat/TL-2026-3892

## SideWinder APT Credential Harvesting Campaign — PaaS Platform Abuse at Scale

**PIR:** 1.j.3

SideWinder APT exploits PhaaS platforms and cloud hosting providers to execute large-scale credential harvesting operations targeting enterprise identity systems. The campaign abuses legitimate PaaS environments to host phishing portals, rotate infrastructure rapidly, and exfiltrate authentication tokens. Defenders should monitor for anomalous cloud resource provisioning, implement zero-trust identity validation, and integrate threat intelligence to block APT-associated hosting clusters.

Source: https://intel.breakglass.tech/post/sidewinder-mhil-zeabur

## n8n Weaponized for Phishing and Device Fingerprinting

**PIR:** 1.d

Open-source automation tools like n8n are being repurposed by threat actors to orchestrate phishing campaigns and perform device fingerprinting at scale. By chaining legitimate workflow nodes, attackers automate credential harvesting, session token extraction, and victim profiling. Defenders should audit third-party automation deployments, restrict outbound connections from workflow engines, and monitor for unauthorized API integrations in identity management systems.

Source: https://labs.cloudsecurityalliance.org/research/csa-research-note-n8n-ai-workflow-phishing-20260416-csa-styl

