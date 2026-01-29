# Cyber Threat Observatory for national identity systems

The observatory serves as a central hub for gathering intelligence, identifying emerging threats, issuing early warnings, and disseminating insight and best practice to stakeholders. This observatory plays an important role in maintaining the security and integrity for any National Digital ID System.

Goal: 
The complexity of modern vulnerability management requires an analysis framework that dynamically combines "exploitability" of the weakness with organisational context, moving beyond the inherent limitations of static severity scores like the CVSS Base Score. 

We argue that modern vulnerability management fails because it prioritises theoretical severity (CVSS) rather than real-world exploitability. Empirical evidence shows that only a small fraction of CVEs are ever exploited, yet defenders waste effort patching thousands of low-utility flaws.

To fix this, we utilise a Work-Averse Attacker (WAA) model, which treats attackers as rational, resource-constrained actors who minimise effort and maximise payoff. From this perspective, a vulnerability only matters if it meaningfully advances an attacker along the kill chain with low effort and high gain.

Core ideas
1. CVSS is a poor predictor of real risk
•	CVSS measures intrinsic technical severity, not likelihood of weaponisation
•	CVSS-only prioritisation performs no better than random patching
•	~6% of CVEs are ever exploited in the wild
•	CVSS ignores deployment context, barriers, and attacker effort=

2. The Work-Averse Attacker (WAA) model
Attackers:
•	Prefer reuse over innovation (low variable cost > high fixed cost)
•	Rarely weaponise multiple bugs per version (“one exploit per version”)
•	Avoid complex, unreliable, or high-effort exploits
•	Update their toolkits only when existing exploits stop working


3. Kill Chain Utility is the primary prioritisation signal
A vulnerability’s priority depends on:
•	Where it fits in the kill chain (initial access vs post-compromise)
•	What barriers exist (auth, MitM, network access, user interaction)
•	What payoff it delivers (RCE, data breach, privilege escalation)
•	How the software is actually deployed (public-facing vs internal)

4-Tier System Logic:
- TIER 1: Immediate external threat, no barriers, high value (initial access, RCE, data breach)
- TIER 2: High value but requires prerequisites (exploited/PoC but can't access from outside immediately, but provides high-impact gain)
- TIER 3: Arsenal value, post-compromise utility, significant prerequisites, or barriers + low impact
- TIER 4: Low kill chain utility, theoretical, or admin-only where legitimate access suffices
