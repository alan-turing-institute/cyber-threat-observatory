# Daily phishing and identity campaigns

- **Report date:** 2026-11-16
- **Sources:** ketch OSINT (3 queries)

## The hidden network: Inside the phishing infrastructure ecosystem powering global cybercrime

**PIR:** 1.a

Analyzes the underlying hosting, domain registration, and monetization layers supporting modern phishing operations. Provides actionable intelligence for infrastructure defenders to map threat actor supply chains, implement proactive DNS sinkholing, and disrupt attacker infrastructure before campaigns scale.

Source: https://microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime

## Inside Tycoon2FA: How a leading AiTM phishing kit operated at scale

**PIR:** 1.b

Dissects a commercial Adversary-in-the-Middle kit that proxies authentication sessions to steal valid MFA tokens. Demonstrates how traditional password-plus-OTP is bypassed and underscores the urgent shift toward phishing-resistant MFA standards like FIDO2 and certificate-based authentication.

Source: https://microsoft.com/en-us/security/blog/2026/03/04/inside-tycoon2fa-how-a-leading-aitm-phishing-kit-operated-at-scale

## Inside an AI‑enabled device code phishing campaign

**PIR:** 1.e

Leverages generative AI to dynamically generate convincing login prompts and device code flows. Bypasses traditional URL filtering and requires behavioral analytics to detect automated consent grants, highlighting gaps in static web proxy defenses and the need for adaptive identity monitoring.

Source: https://microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026

## High volume phishing campaign uses Microsoft 365 outage lures to target multiple industry sectors

**PIR:** 1.d

Exploits real-time service disruptions to trick users into credential submission. Highlights the critical need for rapid, authoritative incident communication channels and conditional access policies that detect anomalous login patterns and impossible travel during documented outages.

Source: https://microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2

## The Hidden Relay: Inside a Device Code Phishing Kit That Never Shows the Code

**PIR:** 1.g

Introduces a novel kit that intercepts device code flows without displaying the code to the victim, using background relays. Challenges traditional detection methods and requires deep packet inspection, API gateway monitoring, and strict OAuth scope limitations to prevent silent token theft.

Source: https://blog.knowbe4.com/the-hidden-relay-inside-a-device-code-phishing-kit-that-never-shows-the-code

## Device Code Phishing is an Evolution in Identity Takeover | Proofpoint US

**PIR:** 1.c

Explains how attackers abuse OAuth device authorization flows to capture tokens without passwords. Critical for identity architects to restrict unnecessary device code grants, monitor for rapid token validation patterns, and implement step-up authentication for sensitive administrative actions.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Microsoft 365 device code phishing campaign bypasses password stealing | RL Blog

**PIR:** 1.f

Details how attackers pivot from credential harvesting to direct token theft via device code abuse. Emphasizes the need to disable unnecessary OAuth grants, implement short token lifetimes, and deploy identity threat detection platforms that flag anomalous device code validation sequences.

Source: https://www.reversinglabs.com/blog/device-code-phishing-campaign

## Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise

**PIR:** 1.b

Analyzes a multi-stage campaign using fake compliance documents to deliver AiTM proxies. Shows how social engineering combines with technical token theft to compromise enterprise accounts, emphasizing the need for email authentication hardening and user training on document verification.

Source: https://microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise

