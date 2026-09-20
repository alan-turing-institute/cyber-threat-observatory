# Daily phishing and identity campaigns

- **Report date:** 2026-09-16
- **Sources:** ketch OSINT (3 queries)

## GhostCode Phishing Kit Bypasses Microsoft 365 MFA to Hijack Accounts in 78 Seconds

**PIR:** 1.d

Threat actors are deploying the GhostCode phishing kit to rapidly bypass Microsoft 365 multi-factor authentication, compromising enterprise accounts in under two minutes. The campaign leverages real-time proxy techniques to intercept MFA prompts, allowing attackers to authenticate as legitimate users. Infrastructure defenders must prioritize blocking unauthorized device code flows and implementing conditional access policies that restrict token issuance from suspicious IP ranges. Monitoring for 

Source: https://cybersecuritynews.com/ghostcode-phishing-kit/amp

## Microsoft 365: Block Device Code Flow Against GhostCode

**PIR:** 1.d

Microsoft has issued urgent guidance to disable the device code authentication flow following widespread abuse by the GhostCode threat group. Attackers exploit this OAuth mechanism to silently register rogue devices and harvest long-lived access tokens, bypassing traditional MFA controls. IT infrastructure teams should immediately configure Azure AD conditional access rules to block device code grants, audit registered devices for unauthorized enrollments, and enforce certificate-based authentic

Source: https://windowsforum.com/news/microsoft-365-block-device-code-flow-against-ghostcode.444973

## Midnight Blizzard-Linked Actor GTG-20006 Automated Device Code Phishing With AI

**PIR:** 1.h

A sophisticated threat actor linked to Midnight Blizzard is leveraging AI-driven automation to scale device code phishing campaigns against Microsoft 365 environments. The group uses machine learning to dynamically generate convincing login portals and optimize credential harvesting workflows. Infrastructure defenders should deploy AI-aware detection models, monitor for rapid sequential authentication attempts, and restrict device code flows to approved corporate networks. Integrating behavioral

Source: https://aegisai.ai/blog/anthropic-midnight-blizzard-ai-device-code-phishing

## Laundry Bear Zero-Click Zimbra Phishing Campaign Warned by CISA

**PIR:** 1.f

CISA has alerted organizations to a zero-click phishing campaign exploiting a critical vulnerability in Zimbra Collaboration Suite. The Russian-linked Laundry Bear group leverages this flaw to silently compromise email accounts without user interaction, enabling data exfiltration and lateral movement. Infrastructure teams must immediately patch Zimbra instances, audit email server logs for unauthorized access, and implement network segmentation to isolate mail systems. Deploying endpoint detecti

Source: https://tempmail.ninja/blog/laundry-bear-zimbra-phishing

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.e

Modern phishing operations increasingly exploit cloud-native services like serverless functions, object storage, and CDN networks to host malicious payloads and evade traditional security controls. Attackers leverage legitimate cloud APIs to dynamically generate phishing domains and distribute credential-harvesting pages at scale. Infrastructure defenders must implement strict cloud security posture management, monitor for anomalous API usage, and enforce egress filtering. Zero-trust network arc

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Microsoft: Passkey Help Desk Calls Are Hijacking Cloud Accounts, Then Draining SharePoint

**PIR:** 1.d

Social engineering attacks are increasingly targeting help desk personnel to manipulate passkey registration processes, resulting in unauthorized cloud account takeovers and SharePoint data drainage. Attackers impersonate legitimate users to request passkey resets, bypassing traditional password-based security. IT infrastructure defenders must enforce strict identity verification protocols for support requests, implement multi-person approval workflows for credential changes, and monitor for ano

Source: https://threat-intelligence.redeyesecurity.com/blog/passkey-phishing-microsoft-cloud-hijack-storm-3032-2026

## Fast Flux Phishing Turns the Internet Into a Moving Target as Silent Push Uncovers a Massive Canada-First Banking Operation + Video - UNDERCODE NEWS

**PIR:** 1.g

Cybercriminals are weaponizing fast-flux DNS networks to create highly resilient phishing infrastructure that rapidly rotates IP addresses and hosting providers. This technique complicates takedown efforts and enables large-scale banking fraud operations targeting Canadian financial institutions. IT defenders should integrate threat intelligence feeds that track fast-flux patterns, deploy DNS-layer filtering, and monitor for rapid domain resolution changes. Implementing email authentication prot

Source: https://undercodenews.com/fast-flux-phishing-turns-the-internet-into-a-moving-target-as-silent-push-uncovers-a-massive-canada-first-banking-operation-video

## PhantomEnigma: How a Malware Crew Turned Brazilian Government Sites Into Trusted Malware Hubs

**PIR:** 1.g

The PhantomEnigma threat group has compromised official Brazilian government websites to host phishing pages and malware distribution hubs, leveraging inherent user trust to bypass security awareness training. Attackers exploit outdated web servers and weak access controls to inject malicious scripts that harvest credentials and deploy ransomware. Defenders should conduct regular third-party risk assessments, implement web application firewalls, and monitor for unauthorized content changes on pu

Source: https://securebulletin.com/phantomenigma-how-a-malware-crew-turned-brazilian-government-sites-into-trusted-malware-hubs

