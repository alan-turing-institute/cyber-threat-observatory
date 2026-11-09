# Daily phishing and identity campaigns

- **Report date:** 2026-11-08
- **Sources:** ketch OSINT (3 queries)

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.j.3

This campaign marks a significant escalation in threat actor sophistication, moving from static scripts to AI-driven infrastructure and end-to-end automation. It builds upon the Storm-2372 device code phishing campaign observed in February 2025, demonstrating how adversaries leverage generative AI to streamline credential harvesting and bypass traditional email security controls. Infrastructure defenders should monitor for automated device code prompts and implement conditional access policies t

Source: https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.j.3

This analysis dissects the EvilTokens infrastructure, revealing how threat actors exploit device code authentication flows to bypass multi-factor authentication and password-based defenses. The report details the technical mechanics of the phishing kit, infrastructure patterns, and detection strategies. IT defenders can use these insights to harden identity providers, deploy real-time alerting for suspicious device code requests, and block known malicious domains associated with the campaign.

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.j.3

Proofpoint examines how device code phishing has evolved into a primary vector for identity takeover, effectively neutralizing traditional MFA implementations. The article outlines attacker tactics, infrastructure reuse, and the shift toward cloud-native authentication exploitation. Defenders are advised to review OAuth consent grants, enforce phishing-resistant MFA, and implement user behavior analytics to detect anomalous authentication patterns across enterprise environments.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.j.3

ReversingLabs details a targeted campaign leveraging Microsoft 365 device code flows to circumvent traditional credential harvesting techniques. By prompting users to authenticate directly on secondary devices, attackers bypass password stealers and capture valid session tokens. The report provides IOCs, infrastructure mappings, and mitigation guidance for securing enterprise identity platforms against this increasingly prevalent authentication bypass method.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## GhostCode: Dissecting a Novel Device Code Phishing Kit | eSentire

**PIR:** 1.j.3

eSentire provides a technical breakdown of the GhostCode phishing kit, which automates device code generation and victim interaction. The analysis covers the kit’s architecture, evasion techniques, and deployment patterns. Infrastructure teams can leverage these findings to update web proxy filters, block associated C2 domains, and educate users on recognizing legitimate versus malicious device code prompts in corporate environments.

Source: https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit

## Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA

**PIR:** 1.a

CISA warns of a highly targeted spearphishing campaign aimed at government bodies, international organizations, and NGOs. The campaign utilizes tailored lures and credential harvesting pages to compromise high-value accounts. Defenders should enforce strict email filtering, monitor for unusual login locations, and ensure privileged accounts utilize phishing-resistant authentication methods to prevent lateral movement and data exfiltration.

Source: https://cisa.gov/news-events/cybersecurity-advisories/aa21-148a

## Russian state-supported cyber actors conduct phishing campaign targeting users of Zimbra collaboration suite

**PIR:** 1.a

The Australian Cyber Security Centre details a state-sponsored phishing campaign exploiting Zimbra collaboration suite users. Attackers deploy malicious links and credential harvesting pages to compromise email accounts. Infrastructure defenders should patch Zimbra instances, monitor for anomalous authentication attempts, and implement network segmentation to limit the impact of compromised collaboration platforms.

Source: https://cyber.gov.au/sites/default/files/2026-07/russian_state-supported_cyber_actors_conduct_phishing_campaign_targeting_users_of_zimbra_collaboration_suite.pdf

## Email scammers posed as DOT officials in phishing messages focused on $1 trillion bill | CyberScoop

**PIR:** 1.j.1

CyberScoop reports on a phishing wave where attackers impersonated Department of Transportation officials, leveraging a major infrastructure funding bill as bait. The campaign targets financial and procurement personnel with malicious attachments and credential harvesting links. Organizations should verify sender authenticity, deploy advanced email security gateways, and conduct targeted awareness training to mitigate financial fraud and identity compromise risks.

Source: https://preprod.cyberscoop.com/inky-dot-infrastructure-bill-phishing-bid

