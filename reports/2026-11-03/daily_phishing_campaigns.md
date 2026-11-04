# Daily phishing and identity campaigns

- **Report date:** 2026-11-03
- **Sources:** ketch OSINT (3 queries)

## Unmasking EvilTokens: Getting to the root of device code phishing | Microsoft Security Blog

**PIR:** 1.c

This deep dive examines the EvilTokens framework, which exploits OAuth device code flows to bypass multi-factor authentication and conditional access policies. The report details how attackers intercept authorization codes, automate token exchange, and maintain persistent access without triggering standard login alerts. Identity and infrastructure defenders receive mitigation steps, including flow monitoring, token lifecycle management, and architectural adjustments to secure device code endpoin

Source: https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime | Microsoft Security Blog

**PIR:** 1.a

This analysis maps the underground hosting and domain registration networks that sustain large-scale phishing operations. Defenders will find actionable intelligence on shared infrastructure patterns, bulletproof hosting providers, and automated domain generation algorithms. The report details how threat actors rotate IP ranges and abuse legitimate DNS services to evade takedowns, offering network teams specific indicators and architectural insights to block malicious traffic at the perimeter.

Source: https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/

## Phishers are hijacking legitimate cloud infrastructure | Securelist

**PIR:** 1.b

Attackers increasingly leverage compromised or misconfigured cloud accounts to host phishing pages and proxy traffic, bypassing traditional web filters. This research outlines detection strategies for cloud-based phishing infrastructure, including identifying anomalous storage bucket configurations, serverless function abuse, and CDN misconfigurations. Infrastructure teams can use these findings to harden cloud environments, implement stricter IAM policies, and deploy behavioral monitoring to ca

Source: https://securelist.com/cloud-platforms-in-phishing/120832/

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.c

An authoritative overview of how device code phishing has matured into a primary identity takeover vector, circumventing traditional MFA and SSO controls. The article explains the technical mechanics of code interception, session hijacking, and automated credential stuffing pipelines. For infrastructure defenders, it provides network-level detection signatures, proxy configuration recommendations, and identity governance controls to limit blast radius and enforce stricter device compliance durin

Source: https://proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Device-code phishing: How real login pages enable attacks

**PIR:** 1.j.3

This technical analysis reveals how attackers leverage legitimate authentication endpoints to harvest device codes, making traditional URL filtering ineffective. The report outlines the proxy architecture used to relay real login pages while capturing authorization tokens in transit. Infrastructure teams learn how to implement TLS inspection, monitor for anomalous OAuth traffic patterns, and deploy conditional access rules that detect rapid code validation attempts, strengthening perimeter and i

Source: https://blog.barracuda.com/2026/11/02/device-code-phishing-real-login-page

## The Infrastructure Behind Phishing | Zerot Security Research

**PIR:** 1.a

A comprehensive breakdown of the technical stack powering modern phishing campaigns, from fast-flux DNS networks to ephemeral container deployments. The article provides defenders with architectural diagrams of attacker infrastructure, highlighting how load balancers, reverse proxies, and automated scaling tools are weaponized. Network and security operations teams gain practical guidance on identifying infrastructure fingerprints, correlating cross-campaign hosting patterns, and implementing pr

Source: https://research.zerot-security.com/the-infrastructure-behind-phishing/

## MadApe: The Code That Opens the Door

**PIR:** 1.d

Group-IB dissects the MadApe phishing kit, a modular toolchain designed specifically for Microsoft 365 device code harvesting. The analysis covers the kit’s backend infrastructure, automated victim tracking, and token exfiltration mechanisms. Defenders gain insight into the kit’s deployment patterns, associated hosting providers, and network indicators. The article provides actionable recommendations for hardening identity providers, monitoring OAuth endpoints, and blocking kit-specific infrastr

Source: https://group-ib.com/blog/madape-microsoft-device-code-phishing-kit

## Inside Wazza: A Newly Observed Device Code Phishing Kit Targeting Microsoft 365 Accounts

**PIR:** 1.d

This research uncovers the Wazza phishing kit, highlighting its use of cloud-native infrastructure and automated domain rotation to evade detection. The report details how the kit captures device codes, manages victim sessions, and integrates with credential stuffing services. Infrastructure defenders receive technical indicators, hosting provider patterns, and network-level blocking strategies. The article emphasizes the need for continuous infrastructure monitoring and identity flow validation

Source: https://www.levelblue.com/blogs/spiderlabs-blog/inside-wazza-a-newly-observed-device-code-phishing-kit-targeting-microsoft-365-accounts

