# Daily phishing and identity campaigns

- **Report date:** 2026-08-12
- **Sources:** ketch OSINT (3 queries)

## OAuth Device Code Phishing: 37x Surge in Enterprise ATO

**PIR:** 1.b

This Cloud Security Alliance report details a 37-fold increase in enterprise account takeovers leveraging OAuth device code flows. Attackers bypass traditional MFA by tricking users into entering short-lived codes on compromised devices. Infrastructure defenders must monitor for anomalous OAuth consent requests, restrict device code grant types in identity providers, and implement conditional access policies that validate device posture alongside code validation.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_oauth-device-code-phishing-surge_20260405-csa-styled.pdf

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.b.2

Level Blue’s SpiderLabs analyzes real-world device code phishing campaigns targeting enterprise SaaS platforms. The report highlights how attackers automate code collection via fake login portals and leverage legitimate OAuth endpoints to authenticate. Defenders should deploy URL filtering for known phishing domains, enforce strict OAuth client registration, and educate users on recognizing device code prompts versus standard login flows.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass

**PIR:** 1.b.3

Trend Micro examines how device code authentication, designed for screenless devices, is weaponized to circumvent multi-factor authentication. Attackers host spoofed portals requesting codes, which are instantly validated against legitimate identity providers. IT infrastructure teams must audit OAuth configurations, disable unnecessary device code grants, and implement behavioral analytics to detect rapid code redemption patterns indicative of automated phishing.

Source: https://trendmicro.com/en/research/26/g/device-code-phishing.html

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave

**PIR:** 1.e

SlashID explores the convergence of illicit consent grants, device code phishing, and AI-driven Phishing-as-a-Service platforms. The analysis reveals how attackers combine automated infrastructure provisioning with social engineering to harvest OAuth tokens. Defenders should enforce strict consent screen policies, monitor for newly registered OAuth applications, and integrate threat intelligence feeds to block AI-generated phishing domains at the DNS level.

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns

**PIR:** 1.c

CYFIRMA investigates how threat actors leverage cloud-native services like serverless functions, object storage, and CDN networks to host phishing infrastructure. This approach evades traditional IP-based blocking and scales rapidly. Infrastructure defenders must implement cloud security posture management, monitor for anomalous resource creation patterns, and enforce strict egress filtering to prevent compromised workloads from serving malicious content.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## The AI Phishing Revolution: From Spray-and-Pray to Autonomous Operations

**PIR:** 1.d

This report outlines the shift from manual phishing campaigns to fully autonomous AI-driven operations. Machine learning models now generate context-aware lures, manage infrastructure lifecycles, and adapt to security controls in real time. Defenders must prioritize AI-enhanced email security gateways, deploy deception technology to feed false data to AI models, and establish continuous monitoring for automated credential harvesting attempts.

Source: https://itsecurityguru.org/2026/05/27/the-ai-phishing-revolution-from-spray-and-pray-to-autonomous-operations

## Hackers Hijack 20+ Government Websites to Deliver Malware Through Trusted Links

**PIR:** 1.f

Cybercriminals compromise legitimate government domains to host phishing pages and malware distribution links, exploiting user trust in official URLs. The attack bypasses reputation-based filtering and email security controls. Infrastructure teams should implement strict web application firewalls, enforce domain integrity checks via DNSSEC, and deploy browser isolation solutions to sandbox interactions with high-trust domains that exhibit anomalous behavior.

Source: https://cybersecuritynews.com/government-websites-deliver-malware/amp

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.g

CISA alerts on a zero-click phishing campaign targeting Zimbra email clients, exploiting rendering vulnerabilities to execute malicious scripts without user interaction. The attack harvests credentials and session tokens directly from the email client. Defenders must prioritize patching Zimbra instances, disable auto-rendering of external content, and implement network segmentation to limit lateral movement if email clients are compromised.

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

