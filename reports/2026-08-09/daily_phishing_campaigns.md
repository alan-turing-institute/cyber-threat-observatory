# Daily phishing and identity campaigns

- **Report date:** 2026-08-09
- **Sources:** ketch OSINT (3 queries)

## The Illicit Consent Grant Part 2: Device-Code Phishing and the AI PhaaS Wave | SlashID Blog

**PIR:** 1.f

Explores the convergence of AI-generated phishing templates and illicit OAuth consent grants via device codes. Attackers automate credential harvesting at scale, bypassing traditional MFA. Infrastructure defenders must audit third-party application permissions, enforce strict conditional access policies, and deploy identity threat detection platforms to monitor anomalous consent requests and token issuance patterns.

Source: https://slashid.com/blog/illicit-consent-grant-part-2

## The Device Code Phishing Tsunami: What We’re Seeing in the Wild

**PIR:** 1.i

Analyzes the rapid escalation of device code phishing campaigns targeting enterprise OAuth flows. Victims are tricked into entering short codes on attacker-controlled portals, granting full account access. IT teams should disable unnecessary device code grant types in identity providers, implement token binding, and monitor for rapid, high-privilege consent approvals across cloud directories.

Source: https://www.levelblue.com/blogs/spiderlabs-blog/the-device-code-phishing-tsunami-what-were-seeing-in-the-wild

## Device Code Phishing: Turning a Convenience Feature Into an MFA Bypass

**PIR:** 1.e

Details how device code authentication flows are weaponized to circumvent multi-factor authentication by leveraging pre-authenticated sessions. Defenders must prioritize identity-centric security controls, enforce step-up authentication for sensitive actions, and restrict device code grants to approved applications only. Network egress filtering and DNS sinkholing remain critical for blocking phishing infrastructure.

Source: https://trendmicro.com/en/research/26/g/device-code-phishing.html

## Device Code Phishing is an Evolution in Identity Takeover

**PIR:** 1.j

Examines how device code phishing facilitates complete identity takeover by capturing valid OAuth tokens rather than raw credentials. Infrastructure teams should deploy user and entity behavior analytics to detect token abuse, enforce short-lived access tokens, and implement continuous authentication. Regular revocation of stale consent grants is essential for mitigating lateral movement risks.

Source: https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover

## Abuse of Cloud-Native Infrastructure in Modern Phishing Campaigns - CYFIRMA

**PIR:** 1.h

Investigates how threat actors leverage serverless functions, object storage, and CDN services to host phishing pages that evade traditional URL filtering. Defenders must implement cloud security posture management, monitor for misconfigured storage buckets, and enforce strict egress controls. Integrating cloud-native telemetry with SIEM platforms enables rapid detection of malicious infrastructure provisioning.

Source: https://cyfirma.com/research/abuse-of-cloud-native-infrastructure-in-modern-phishing-campaigns

## Tycoon2FA Returns: PhaaS Platform Survives Law Enforcement Disruption

**PIR:** 1.g

Documents the operational resilience of the Tycoon2FA Phishing-as-a-Service platform following law enforcement takedowns. Attackers rapidly migrate infrastructure and reuse templated campaigns. Security operations centers should update threat intelligence feeds with known PhaaS indicators, block associated domains at the proxy level, and educate users on recognizing cloned login portals.

Source: https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_Tycoon2FA-PhaaS-resurrection-MaaS-resilience-20260326-csa-styled.pdf

## Device Code Phishing — The Attack That Makes MFA Irrelevant

**PIR:** 1.i

Breaks down the technical mechanics of device code phishing campaigns that render traditional step-up authentication ineffective. Attackers exploit OAuth 2.0 device authorization flows to capture session tokens. Infrastructure defenders should enforce certificate-based authentication, disable device code grants where possible, and implement real-time alerting for unusual consent grant patterns across identity providers.

Source: https://cybergrind.org/blog/2026-06-02-device-code-phishing

## Sophisticated Spearphishing Campaign Targets Government Organizations, IGOs, and NGOs | CISA

**PIR:** 1.a

CISA advisory detailing targeted spearphishing operations using malicious documents and credential harvesting sites. Defenders must deploy advanced email security gateways with attachment sandboxing, enforce strict URL rewriting, and implement user awareness training. Monitoring for anomalous outbound connections to newly registered domains helps identify early-stage compromise attempts.

Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a

