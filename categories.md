# Kill Chain Applicability: Threat Adjustment Categories

**Live Document** - This document provides dynamic guidance for adjusting vulnerability threat scores based on kill chain applicability and real-world exploitation factors. Update this document as new attack patterns, threat intelligence, and empirical evidence emerge.

## Overview

**IMPORTANT: This document is for FINE-TUNING your assessment, not the starting point.**

This document complements the Work-Averse Attacker (WAA) methodology by providing specific, actionable rules for when to **increase** or **decrease** threat priority based on kill chain utility. However, **you must first conduct Software Assessment and then assess Kill Chain applicability** by thinking like an attacker:

**STEP 0: Software Assessment (REQUIRED FIRST)**
1. **Network Reachability:** Is the software network-reachable? Is it often network-enabled? Or is it a local tool only?
2. **Deployment Context:** What is the software's primary application? Where is it typically deployed? (Public-facing, internal, backend processing, IoT, etc.)
3. **Execution Context:** What privilege level does the software run as? (Root/admin, system/service, standard user) Is it containerized?
4. **Application-Specific Context:** If backend processing tool, where deployed? If network service, what protocols? If local tool, what access required?

**STEP 1: Kill Chain Analysis**
1. **Start with Kill Chain Analysis:** "Where can I use this vulnerability? What value does it bring to me as an attacker?" (Use software assessment information)
2. **Assess from Attacker Perspective:** 
   - Can I use this for initial access from outside? (High kill chain utility)
   - Do I need to already be on the network? (Lower kill chain utility - requires network access)
   - Do I need authentication first? (Lower kill chain utility - requires credential compromise)
   - Can I only use this after I have access? (Post-compromise utility)
   - **How does the software's network reachability, deployment, and execution context affect exploitability?**

**STEP 2: Category Fine-Tuning**
3. **Then Apply Category Fine-Tuning:** Use the categories below to adjust your assessment based on specific factors (authentication, MitM, impact level, deployment scenario, execution context, etc.)

**The categories are supporting tools to refine your kill chain assessment, not the primary assessment method.** Always begin with the attacker perspective: "Where can I use this? What value does it bring?"

Each category includes the rationale aligned with WAA economic principles.

---

## 🔴 DECREASE THREAT PRIORITY (Lower Kill Chain Utility)

### Authentication Requirements

#### **Category A1: Admin-Only Authentication Required**
- **Adjustment:** Decrease by **2 tiers** (e.g., TIER 1 → TIER 3, TIER 2 → TIER 4) or assign directly to **TIER 4**
- **Rationale:** Administrators already possess legitimate means to perform most actions. The WAA will not invest effort in exploiting vulnerabilities when existing privileges suffice.
- **Exception:** Maintain higher priority if the vulnerability enables **privilege escalation from non-admin accounts** (e.g., standard user → admin), as this represents an external-to-internal attack vector.
- **Examples:**
  - SQL injection in admin panel requiring admin login
  - File upload vulnerability accessible only to administrators
  - Configuration manipulation requiring root/system privileges

#### **Category A2: All Authenticated Users Required**
- **Adjustment:** Decrease by **1 tier** (e.g., TIER 1 → TIER 2, TIER 2 → TIER 3, TIER 3 → TIER 4)
- **Rationale:** Requires insider access or compromised credentials, increasing attacker fixed costs. External WAA actors prefer unauthenticated attack vectors.
- **Considerations:**
  - If credential compromise is trivial (e.g., default passwords, weak authentication), maintain original tier
  - If the vulnerability affects a large user base (e.g., all employees), consider insider threat scenarios but still reduce external threat priority
- **Examples:**
  - Cross-site scripting (XSS) requiring user login
  - Information disclosure in authenticated user dashboard
  - Session fixation affecting logged-in users

### Attack Complexity and Reliability

#### **Category B1: High Attack Complexity**
- **Adjustment:** Decrease by **1 tier** if complexity significantly impacts reliability
- **Rationale:** WAA prioritises reliability and repeatability. Complex exploits increase fixed costs and failure risk.
- **Indicators:**
  - Race conditions requiring precise timing
  - Memory layout dependencies (ASLR bypass requirements)
  - Multi-stage exploitation chains with high failure rates
- **Examples:**
  - Use-after-free requiring specific heap grooming
  - Time-of-check-time-of-use (TOCTOU) race conditions
  - Complex buffer overflow requiring multiple memory corruption steps

#### **Category B2: Exploit Instability**
- **Adjustment:** Decrease by **1 tier** if instability causes frequent failures
- **Rationale:** Unreliable exploits increase detection risk and campaign failure, reducing WAA utility.
- **Indicators:**
  - Exploits causing system crashes >10% of attempts
  - Requiring multiple retry attempts (>5) for success
  - Platform-specific failures on common configurations
- **Examples:**
  - Exploits that crash the target service frequently
  - Memory corruption that requires multiple attempts to achieve code execution
  - Exploits that fail on patched but vulnerable configurations

### Platform and Configuration Dependencies

#### **Category C1: Obscure Platform/Configuration Requirements**
- **Adjustment:** Decrease by **1 tier** if requirements are rare in production environments
- **Rationale:** Limited attack surface reduces WAA return on investment for exploit development.
- **Indicators:**
  - Requires specific OS versions with <5% market share
  - Depends on non-default configuration settings
  - Only exploitable on deprecated or rarely-used features
- **Examples:**
  - Vulnerability affecting only legacy Windows Server 2003
  - Exploit requiring specific compiler flags or build configurations
  - Issues in disabled-by-default features

### Network-Level Access Requirements

#### **Category N1: Man-in-the-Middle (MitM) / Network-Level Access Required**
- **Adjustment:** Decrease by **2 tiers** or assign to **TIER 3** unless provides high-impact gain beyond network interception
- **Rationale:** Network-level access (MitM position, network spoofing, ARP poisoning, compromised network infrastructure) is a **significant barrier** that requires the attacker to already have network-level access or compromise network infrastructure. This is difficult to achieve and represents high attacker fixed costs. External attackers cannot exploit these vulnerabilities without first establishing network-level access.
- **Critical Rule:** Plaintext credential transmission vulnerabilities that **require MitM** to intercept are **not** "no barriers" - they require network-level access, which is a significant barrier. Combined with limited impact (credential interception only, not direct authentication bypass), these should be **TIER 3**, not TIER 1 or TIER 2.
- **Indicators:**
  - Requires Man-in-the-Middle (MitM) position on network
  - Requires network-level access (router compromise, network infrastructure access)
  - Requires ARP spoofing or network traffic interception
  - Plaintext credential transmission requiring network interception
  - Network sniffing requirements
- **Examples:**
  - Plaintext HTTP credential transmission (requires MitM to intercept)
  - Unencrypted protocol vulnerabilities requiring network interception
  - Vulnerabilities requiring compromised network infrastructure
  - Network-level traffic analysis requirements
- **Exception:** If the vulnerability provides **direct authentication bypass** without requiring MitM (e.g., direct API access that bypasses authentication), it may maintain higher priority. However, if it only enables credential interception via MitM, it is **TIER 3**.

### Theoretical vs. Practical Exploitation

#### **Category D1: Purely Theoretical (No PoC, No Active Exploitation)**
- **Adjustment:** Assign to **TIER 4** regardless of CVSS score
- **Rationale:** Empirical evidence shows only 6.4% of vulnerabilities are exploited. Without proof of weaponisation, the WAA will not invest in exploitation.
- **Indicators:**
  - No public Proof-of-Concept (PoC) code
  - No active exploitation observed in threat intelligence
  - Low EPSS score (<0.1)
  - Academic or theoretical attack vectors only
- **Examples:**
  - Complex cryptographic vulnerabilities with no practical exploit
  - Theoretical side-channel attacks requiring laboratory conditions
  - Vulnerabilities requiring attacker-controlled infrastructure that is impractical

---

## 🟢 INCREASE THREAT PRIORITY (Higher Kill Chain Utility)

### Active Exploitation

#### **Category E1: Actively Exploited in the Wild (No Barriers)**
- **Adjustment:** Increase to **TIER 1** regardless of other factors
- **Rationale:** Active exploitation demonstrates proven kill chain utility. The WAA has already invested in weaponisation, indicating high return on effort. If no significant barriers exist, this is an immediate threat.

#### **Category E2: Actively Exploited in the Wild (With Barriers/Prerequisites)**
- **Adjustment:** Assign to **TIER 2** ONLY if provides **high-impact gain** (RCE, data breach, privilege escalation to admin). Otherwise assign to **TIER 3**.
- **Rationale:** Active exploitation proves utility, but significant prerequisites (authentication, privilege escalation only, insider access) prevent immediate external exploitation. **Critical:** If the vulnerability only provides low-impact gain (client-side attacks, phishing, content manipulation without code execution), it should be **TIER 3** regardless of active exploitation status.
- **High-Impact Gain Required for TIER 2:**
  - Remote Code Execution (RCE)
  - Data breach (sensitive data access)
  - Privilege escalation to admin/system level
  - System compromise
- **Low-Impact Gain (TIER 3):**
  - Client-side attacks only (XSS, clickjacking)
  - Phishing facilitation
  - Content manipulation without code execution
  - Limited information disclosure
  - Local privilege escalation (post-compromise)
- **Indicators:**
  - Confirmed exploitation in threat intelligence feeds
  - Ransomware or APT campaigns using the vulnerability
  - Exploitation kits including the vulnerability
  - CISA KEV (Known Exploited Vulnerabilities) listing
- **Examples:**
  - Log4Shell (CVE-2021-44228) - widespread exploitation
  - ProxyLogon (CVE-2021-26855) - used by APT groups
  - Zero-day vulnerabilities in active campaigns

### Exploit Availability

#### **Category F1: Public PoC with High Reliability (No Barriers)**
- **Adjustment:** Increase to **TIER 1** or increase by **1 tier** if PoC is reliable and easy to use with no prerequisites
- **Rationale:** Public PoCs reduce attacker fixed costs to near zero, making exploitation attractive to WAA actors. If unauthenticated and network-accessible, this represents immediate threat.
- **GitHub Reference Assessment:** If a GitHub URL is referenced, **lookup and assess the actual repository content**. Only treat as "Public PoC with High Reliability" if:
  - Repository contains **ready-to-use exploit code** (executable scripts, complete code)
  - OR contains **detailed writeup with sufficient technical details** that enables easy exploit development
  - Do NOT treat basic writeups or incomplete information as "public PoC available" - this overstates exploitation likelihood

#### **Category F1b: Public PoC with High Reliability (With Barriers)**
- **Adjustment:** Assign to **TIER 2** ONLY if PoC provides **high-impact gain** (RCE, data breach, privilege escalation to admin) despite barriers. If barriers exist and impact is **low** (client-side, phishing, content manipulation), assign to **TIER 3**.
- **Rationale:** Public PoC reduces development costs, but prerequisites create barriers that prevent immediate external exploitation. **Critical Rule:** Barriers + Low Impact Gain = Never TIER 2. Even with public PoC, if the vulnerability only enables client-side attacks, phishing, or content manipulation without code execution, it belongs in TIER 3 (Arsenal Value), not TIER 2.
- **Examples of TIER 3 (Barriers + Low Impact):**
  - Authenticated XSS (requires login, only client-side impact)
  - IDOR allowing content manipulation (requires authentication, no code execution)
  - Phishing facilitation vulnerabilities (requires authenticated access)
  - Client-side clickjacking (requires user interaction and authentication)
- **Indicators:**
  - PoC available on GitHub, Exploit-DB, or similar platforms
  - PoC requires minimal modification (<10 lines of code)
  - PoC success rate >80% on default configurations
  - PoC included in automated exploitation frameworks (Metasploit, etc.)
- **GitHub Reference Assessment:** If a GitHub URL is referenced, **lookup and assess the actual repository content** (see Methodology Section A.1). Only treat as "Public PoC with High Reliability" if:
  - Repository contains **ready-to-use exploit code** (executable scripts, complete code)
  - OR contains **detailed writeup with sufficient technical details** that enables easy exploit development
  - Do NOT treat basic writeups, incomplete information, or conceptual descriptions as "public PoC available"
- **Examples:**
  - Metasploit modules for the vulnerability
  - One-line command exploits
  - Automated scanner plugins
  - Complete GitHub repositories with functional exploit code

#### **Category F2: Exploit in Cybercrime Markets**
- **Adjustment:** Increase to **TIER 1** or **TIER 2** depending on market availability and prerequisites
- **Rationale:** Commercial exploit availability indicates proven utility and reduces WAA development costs.
- **Indicators:**
  - Exploit available on dark web markets
  - Exploit-as-a-Service offerings
  - Ransomware-as-a-Service including the exploit
- **Examples:**
  - Exploits sold on underground forums
  - RaaS platforms incorporating the vulnerability

### High EPSS Scores

#### **Category G1: Very High EPSS Score (>0.9, No Barriers)**
- **Adjustment:** Increase to **TIER 1** or increase by **1 tier** if EPSS >0.9, no active exploitation yet, and no significant prerequisites
- **Rationale:** EPSS demonstrates strong predictive power (AUC 0.7795). Very high scores indicate imminent exploitation likelihood when no barriers exist.

#### **Category G1b: Very High EPSS Score (>0.9, With Barriers)**
- **Adjustment:** Assign to **TIER 2** ONLY if EPSS >0.9, barriers exist, AND provides **high-impact gain** (RCE, data breach, privilege escalation to admin). If barriers exist and impact is **low**, assign to **TIER 3**.
- **Rationale:** High predictive value but prerequisites prevent immediate external exploitation. **Critical Rule:** Barriers + Low Impact Gain = Never TIER 2. Even with high EPSS, if the vulnerability only provides client-side attacks, phishing facilitation, or content manipulation without code execution, it belongs in TIER 3.

### Privilege Escalation Vectors

#### **Category H1: Enables Privilege Escalation (With Initial Access Required)**
- **Adjustment:** Typically **TIER 2** or **TIER 3** depending on prerequisites. If it enables escalation from unauthenticated or low-privilege access, may qualify for **TIER 2**. If it requires authenticated access first, typically **TIER 3**.
- **Rationale:** Privilege escalation provides significant attacker gain, but requires initial access. These are high-value post-compromise tools but not immediate external threats. The WAA values these for multi-stage attacks but they don't provide initial access vectors.
- **Examples:**
  - Local privilege escalation vulnerabilities (require initial system access)
  - Container escape vulnerabilities (require container access)
  - Kernel-level vulnerabilities accessible from user space (require user-level access)

### Post-Compromise Utility

#### **Category L1: Post-Compromise Arsenal Value**
- **Adjustment:** Assign to **TIER 3** - Arsenal value, post-compromise utility
- **Rationale:** These vulnerabilities are valuable to attackers who have already gained access but provide no initial attack vector. The WAA includes these in their toolkit for use after establishing a foothold, but they don't justify immediate patching priority for external defense.
- **Indicators:**
  - Requires authenticated access or local system access
  - Enhances attacker capabilities but doesn't provide initial access
  - Useful for lateral movement or maintaining persistence
  - Requires specific configurations or user interactions
- **Examples:**
  - Information disclosure vulnerabilities in authenticated areas
  - Session management flaws requiring user login
  - Configuration manipulation requiring admin access
  - Vulnerabilities in internal-only services
  - Local privilege escalation vulnerabilities (post-compromise)
  - Container escape vulnerabilities (require container access)
  - Kernel-level vulnerabilities accessible from user space (require user-level access)

### Deployment Scenario Considerations

#### **Category D1: Public-Facing Deployment (Internet-Accessible)**
- **Adjustment:** Maintain or increase priority if vulnerability is unauthenticated and software is typically public-facing
- **Rationale:** Public-facing software is accessible from the internet, providing maximum attack surface for external attackers. Unauthenticated vulnerabilities in public-facing software have the highest kill chain utility.
- **Indicators:**
  - Software typically deployed on internet-facing servers
  - Web applications accessible from public internet
  - Cloud services with public endpoints
  - Public APIs or services
  - Software commonly exposed to internet (e.g., web servers, CMS platforms)
- **Examples:**
  - WordPress websites (typically public-facing)
  - Public web applications
  - Cloud services (SaaS applications)
  - Public APIs
  - Internet-facing network services
- **Kill Chain Impact:**
  - Unauthenticated vulnerabilities in public-facing software = Maximum kill chain utility (TIER 1 potential)
  - Authenticated vulnerabilities in public-facing software = Still higher utility than internal-only (TIER 2 potential if high impact)

#### **Category D2: LAN/Internal-Only Deployment (Behind Firewall)**
- **Adjustment:** Decrease by **1 tier** if software is typically deployed only on internal networks (LAN, behind firewall)
- **Rationale:** Internal-only software requires network-level access first, which is a significant barrier. Even unauthenticated vulnerabilities require the attacker to already be on the network or compromise network infrastructure, reducing kill chain utility for external attackers.
- **Indicators:**
  - Software typically deployed on internal networks only
  - Behind corporate firewalls
  - Not accessible from public internet
  - Internal services (intranet applications)
  - Enterprise software not exposed externally
- **Examples:**
  - Internal file servers
  - Intranet applications
  - Internal management interfaces
  - Enterprise software behind VPN/firewall
  - Internal database systems
- **Kill Chain Impact:**
  - Unauthenticated vulnerabilities in internal-only software = Lower kill chain utility (requires network access first, TIER 2 or TIER 3)
  - Still valuable for lateral movement and post-compromise scenarios
  - May be valuable for insider threats or compromised network scenarios

#### **Category D3: IoT Devices (Special Deployment Considerations)**
- **Adjustment:** Assess based on typical IoT deployment patterns. If typically exposed to internet, maintain or increase priority. If typically behind firewall, decrease by 1 tier.
- **Rationale:** IoT devices have unique deployment patterns that affect kill chain utility:
  - **Often exposed to internet** for remote access (cameras, smart devices)
  - **Mass deployment** provides economies of scale for attackers
  - **Botnet potential** - compromised IoT devices are valuable for DDoS and other campaigns
  - **Weak security** - often have default credentials, unpatched firmware
  - **Wide attack surface** - millions of devices with same vulnerabilities
- **Indicators:**
  - IP cameras, smart home devices, industrial IoT
  - Often exposed to internet for remote access
  - Mass deployment (thousands to millions of devices)
  - Typically unpatched or rarely updated
  - Used in botnet campaigns
- **Examples:**
  - IP cameras (often exposed to internet)
  - Smart home devices (IoT thermostats, lights, etc.)
  - Industrial IoT devices
  - Router/firewall devices
  - Embedded systems with network connectivity
- **Kill Chain Impact:**
  - **Internet-exposed IoT** with unauthenticated vulnerabilities = High kill chain utility (TIER 1 potential) due to mass exploitation potential
  - **IoT botnet value** - compromised devices valuable for wider campaigns (DDoS, credential stuffing, etc.)
  - **Mass exploitation** - economies of scale make even low-impact vulnerabilities attractive
  - **Network access** - IoT devices often provide network-level access for lateral movement
- **Special Considerations:**
  - Even if vulnerability requires authentication, IoT devices often have default credentials (reduces barrier)
  - IoT vulnerabilities are attractive for botnet operators seeking large-scale compromise
  - Consider wider campaign utility (not just individual device compromise)

### Local Tools Requiring Environment Access

#### **Category O1: Local Tool - No Privilege Escalation, No Code Execution**
- **Adjustment:** Assign to **TIER 4** - No threat value, not useful as arsenal tool
- **Rationale:** Vulnerabilities in local tools that require the attacker to already have access to the environment and that do not enable privilege escalation or code execution provide no additional value to attackers. If an attacker already has access, they can achieve objectives through legitimate means without exploiting the vulnerability. These vulnerabilities are not useful in an attacker's toolkit.
- **Indicators:**
  - Vulnerability is in a **local tool** (requires access to the environment/system)
  - Attacker must **already have access** to exploit the vulnerability
  - Vulnerability **does not enable privilege escalation** (not used in privilege escalation contexts)
  - Vulnerability **does not allow code execution** (cannot execute arbitrary code)
  - Vulnerability does not provide significant value beyond what legitimate access already provides
- **Examples:**
  - Local utility tool vulnerabilities that only allow information disclosure when attacker already has access
  - Local tool vulnerabilities requiring admin access but not enabling privilege escalation or code execution
  - Local application vulnerabilities that don't enhance attacker capabilities beyond legitimate access
  - Command-line tool vulnerabilities that require local access but don't enable code execution or privilege escalation
- **Kill Chain Impact:**
  - **No initial access vector** - requires access first
  - **No privilege escalation** - doesn't enable escalation
  - **No code execution** - doesn't enable arbitrary code execution
  - **No arsenal value** - provides no additional capabilities beyond legitimate access
  - **Result:** TIER 4 - No threat value, not useful as an arsenal tool

#### **Category O2: Internal/Local Denial of Service (DoS) Attacks**
- **Adjustment:** Assign to **TIER 4** - No real-world application, not useful in attacker toolkits
- **Rationale:** Denial of Service vulnerabilities that require internal network access or affect local, non-network-reachable software have **no real-world application**. Once inside the network, attackers want to **stay silent and not disrupt anything**. Internal DoS attacks are counterproductive because:
  - **Disruption draws attention** and increases detection risk
  - **Not useful in attacker toolkits** - attackers with network access want persistence and data exfiltration, not service disruption
  - **No kill chain utility** - DoS from inside provides no value since attackers already have access
  - **Counterproductive behavior** - goes against attacker goals of staying undetected
- **Indicators:**
  - Vulnerability causes **Denial of Service** (service disruption, availability impact)
  - Requires **internal network access** (attacker must already be inside the network)
  - OR affects **local, non-network-reachable software** (software not accessible from the network)
  - Cannot be exploited from outside the network
- **Examples:**
  - DoS vulnerabilities in local services requiring network access
  - DoS vulnerabilities in non-network-reachable software
  - Internal DoS that requires being on the network first
  - Local application DoS that requires local/system access
- **Kill Chain Impact:**
  - **No initial access vector** - requires network access first
  - **Counterproductive** - disruption increases detection risk
  - **No utility** - attackers already have access, don't need to disrupt
  - **Not useful in toolkits** - goes against attacker goals of staying silent
  - **Result:** TIER 4 - No real-world application, not useful in attacker toolkits
- **Exception:** External DoS vulnerabilities (exploitable from outside the network) may have value for DDoS campaigns or external disruption, but these are rare and should be assessed on a case-by-case basis. Internal/local DoS = Always TIER 4.

### Client-Side and Limited Impact Attacks

#### **Category M1: Client-Side Only / Phishing Facilitation (With Barriers)**
- **Adjustment:** Assign to **TIER 3** or **TIER 4** depending on prerequisites. If requires authentication, typically **TIER 3**. If admin-only, typically **TIER 4**.
- **Rationale:** Client-side attacks (XSS, clickjacking) and phishing facilitation vulnerabilities require user interaction and provide limited impact compared to code execution or data breach. When combined with authentication barriers, these represent post-compromise utility at best, not immediate external threats.
- **Critical Rule:** Barriers + Client-Side/Low Impact = Never TIER 1 or TIER 2, regardless of active exploitation or public PoC availability.
- **Indicators:**
  - Cross-site scripting (XSS) requiring authentication
  - Clickjacking vulnerabilities requiring user interaction
  - Phishing facilitation (e.g., IDOR allowing content manipulation for phishing)
  - Content manipulation without code execution
  - Client-side only attacks
- **Examples:**
  - Authenticated XSS in user dashboard
  - IDOR allowing field modification (no code execution, only content manipulation)
  - Clickjacking requiring user login and interaction
  - Phishing page manipulation via authenticated vulnerability
  - Client-side template injection requiring authentication

#### **Category M2: Information Disclosure (View-Only) / Authentication Bypass (Read-Only)**
- **Adjustment:** Assign to **TIER 3** or **TIER 4** depending on prerequisites and barriers. If requires MitM or network-level access, typically **TIER 3**. If requires authentication, typically **TIER 3**.
- **Rationale:** Vulnerabilities that only allow **viewing** settings, configurations, or information **without modification capability** are **low-impact gain**. Information disclosure (read-only access) does not provide code execution, data breach of stored data, or system compromise. When combined with barriers (MitM, authentication, network requirements), these should **never** be TIER 1 or TIER 2.
- **Critical Rule:** Barriers + View-Only Information Disclosure = Never TIER 1 or TIER 2, regardless of active exploitation or public PoC availability.
- **Indicators:**
  - Authentication bypass that only allows viewing settings (not modifying)
  - Information disclosure vulnerabilities (read-only access)
  - Configuration viewing without modification capability
  - Settings exposure without change capability
- **Examples:**
  - Authentication bypass allowing view-only access to device settings
  - Plaintext credential transmission requiring MitM (only enables credential interception, not direct bypass)
  - API endpoint that exposes configuration in plaintext but requires MitM to intercept
  - Unauthenticated access to view-only settings pages
- **Note:** If the vulnerability enables **modification** (not just viewing), it may have higher impact. However, if it only enables **viewing** and requires barriers (MitM, authentication, etc.), it is **TIER 3**.

### Network-Accessible, Unauthenticated

#### **Category I1: Network-Accessible, No Authentication**
- **Adjustment:** Maintain or increase priority—this is the **highest kill chain utility** scenario
- **Rationale:** Maximum attack surface with minimal attacker effort. The WAA's ideal attack vector.
- **Indicators:**
  - Exploitable over network (remote)
  - No authentication required
  - No user interaction required
- **Examples:**
  - Remote code execution without authentication
  - Unauthenticated SQL injection
  - Network service buffer overflows

### Mass Exploitation Potential

#### **Category J1: Suitable for Mass Exploitation Campaigns (No Barriers)**
- **Adjustment:** Increase to **TIER 1** or increase by **1 tier** if suitable for automated, large-scale attacks with no prerequisites
- **Rationale:** Mass exploitation provides economies of scale for WAA actors, maximising return on fixed exploit development costs. If unauthenticated and network-accessible, this is immediate threat.

#### **Category J1b: Suitable for Mass Exploitation Campaigns (With Barriers)**
- **Adjustment:** Assign to **TIER 2** ONLY if suitable for mass exploitation, requires prerequisites, AND provides **high-impact gain** (RCE, data breach). If barriers exist and impact is **low** (client-side, phishing, content manipulation), assign to **TIER 3**.
- **Rationale:** High value for large-scale attacks but prerequisites limit immediate external exploitation. **Critical Rule:** Barriers + Low Impact Gain = Never TIER 2. Even if suitable for mass exploitation via credential stuffing, if the vulnerability only enables client-side attacks or content manipulation without code execution, it belongs in TIER 3.
- **Indicators:**
  - Affects widely-deployed software (e.g., web servers, CMS platforms)
  - Exploitable via automated scanners
  - Low detection rate in common security tools
  - Suitable for botnet deployment
- **Examples:**
  - Vulnerabilities in WordPress plugins with millions of installations
  - Web application vulnerabilities scannable by automated tools
  - IoT device vulnerabilities affecting large device populations

---

## ⚖️ NEUTRAL FACTORS (No Adjustment)

### Category K1: Factors That Do Not Change Priority

These factors, while important for other security considerations, do not directly impact kill chain utility from a WAA perspective:

- **CVSS Base Score Alone:** CVSS scores are poor predictors of exploitation (AUC 0.051). Do not adjust based solely on CVSS.
- **Theoretical Impact Severity:** High theoretical impact (e.g., "complete system compromise") does not increase priority if exploitation is impractical.
- **Vendor Severity Ratings:** Vendor ratings may be inflated for business reasons and do not reflect kill chain utility.
- **Media Attention:** Publicity does not correlate with actual exploitation risk.

---

## 📊 Decision Matrix

| Factor | Adjustment | Rationale |
|--------|-----------|-----------|
| Admin-only auth required | -2 tiers or TIER 4 | Admins can achieve objectives legitimately |
| All-user auth required | -1 tier | Requires insider access or credential compromise |
| Active exploitation (no barriers) | TIER 1 | Proven kill chain utility, immediate threat |
| Active exploitation (with barriers + high impact) | TIER 2 | Proven utility, requires prerequisites, but provides RCE/data breach |
| Active exploitation (with barriers + low impact) | TIER 3 | Proven utility but barriers + client-side/phishing only = not TIER 2 |
| Public reliable PoC (no barriers) | TIER 1 or +1 tier | Reduces attacker fixed costs to near zero |
| Public reliable PoC (with barriers + high impact) | TIER 2 | High value, significant prerequisites, but provides RCE/data breach |
| Public reliable PoC (with barriers + low impact) | TIER 3 | Barriers + client-side/phishing = never TIER 2 |
| High EPSS (>0.9, no barriers) | +1 tier or TIER 1 | Strong predictive indicator |
| High EPSS (>0.9, with barriers + high impact) | TIER 2 | Predictive, requires prerequisites, but provides RCE/data breach |
| High EPSS (>0.9, with barriers + low impact) | TIER 3 | Barriers + low impact = never TIER 2 |
| Privilege escalation (post-compromise) | TIER 2 or TIER 3 | High attacker gain but requires initial access |
| Post-compromise arsenal value | TIER 3 | Useful after access gained, no initial vector |
| Client-side/phishing (with barriers) | TIER 3 or TIER 4 | Never TIER 1 or TIER 2, regardless of PoC/exploitation |
| Network, unauthenticated | TIER 1 | Maximum kill chain utility |
| High complexity | -1 tier | Increases attacker fixed costs |
| Exploit instability | -1 tier | Reduces reliability, increases detection risk |
| Obscure platform | -1 tier | Limited attack surface |
| MitM/Network-level access required | -2 tiers or TIER 3 | Significant barrier, requires network compromise |
| Plaintext transmission (requires MitM) | TIER 3 | MitM barrier + credential interception only = not TIER 1/2 |
| Public-facing deployment (unauthenticated) | Maintain/Increase | Maximum kill chain utility for external attackers |
| LAN/Internal-only deployment | -1 tier | Requires network access first, lower kill chain utility |
| IoT device (internet-exposed) | Maintain/Increase | Mass exploitation potential, botnet value |
| IoT device (behind firewall) | -1 tier | Still valuable for botnets but requires network access |
| Local tool (no priv esc, no code exec) | TIER 4 | No threat value, not useful as arsenal tool |
| Internal/Local DoS (requires network access) | TIER 4 | No real-world application, counterproductive |
| Information disclosure (view-only) | TIER 3 or TIER 4 | Low-impact gain, especially with barriers |
| Authentication bypass (view-only) | TIER 3 | View-only = low impact, not system compromise |
| Purely theoretical | TIER 4 | No proof of weaponisation |
| **Barriers + Low Impact Gain** | **Never TIER 1/2** | **Critical rule: Always TIER 3 or TIER 4** |

---

## 🔄 Update Log

- **2025-01-26:** Initial document creation with authentication-based adjustments and kill chain utility categories
- **2025-01-26:** Added GitHub exploit reference assessment requirement
  - Added Methodology Section A.1: GitHub Exploit Reference Assessment
  - Requires analysts to lookup and assess actual GitHub repository content
  - Distinguishes between ready-to-use exploit code, detailed writeups, and basic writeups
  - Updated Category F1 and F1b to reference GitHub assessment methodology
  - Prevents overstating exploitation likelihood from basic writeups or incomplete information
- **2025-01-26:** Expanded from 3-tier to 4-tier system:
  - TIER 1: IMMEDIATE (unchanged)
  - TIER 2: HIGH VALUE BUT BARRIERED (exploited/PoC but significant prerequisites)
  - TIER 3: ARSENAL VALUE (post-compromise utility, significant prerequisites)
  - TIER 4: SCHEDULED (low kill chain utility, theoretical)
- **2025-01-26:** Added critical rule: **Barriers + Low Impact Gain = Never TIER 1 or TIER 2**
  - Clarified that TIER 2 requires high-impact gain (RCE, data breach, privilege escalation to admin) even with barriers
  - Added Category M1 for client-side/phishing-only vulnerabilities with barriers
  - Updated all barrier categories to require high-impact gain for TIER 2 classification
  - Examples: Authenticated XSS, IDOR with content manipulation only, phishing facilitation = TIER 3, not TIER 2
- **2025-01-26:** Added network-level access requirements and information disclosure categories
  - Added Category N1: Man-in-the-Middle (MitM) / Network-Level Access Required
  - Clarified that plaintext credential transmission requiring MitM is **not** "no barriers" - it requires network-level access (significant barrier)
  - Added Category M2: Information Disclosure (View-Only) / Authentication Bypass (Read-Only)
  - Clarified that view-only access (information disclosure without modification) is low-impact gain
  - Examples: Plaintext credential transmission requiring MitM = TIER 3, Authentication bypass (view-only) = TIER 3
- **2025-01-26:** Emphasized Kill Chain applicability as primary factor
  - Updated methodology to require starting with attacker perspective: "Where can I use this? What value does it bring?"
  - Clarified that categories are for fine-tuning after kill chain assessment, not the starting point
  - Added assessment flow: Kill Chain Analysis → Attacker Value Assessment → Category Fine-Tuning
- **2025-01-26:** Added deployment scenario assessment
  - Added Category D1: Public-Facing Deployment (Internet-Accessible)
  - Added Category D2: LAN/Internal-Only Deployment (Behind Firewall) - Decrease by 1 tier
  - Added Category D3: IoT Devices (Special Deployment Considerations)
  - Emphasized deployment scenario as key factor in kill chain assessment
  - Added deployment scenario questions to assessment flow
  - Clarified that LAN/internal-only deployment reduces kill chain utility (requires network access first)
  - Special considerations for IoT devices: mass exploitation, botnet value, often internet-exposed
- **2025-01-26:** Added local tool assessment category
  - Added Category O1: Local Tool - No Privilege Escalation, No Code Execution
  - Clarified that local tools requiring environment access but not enabling privilege escalation or code execution = TIER 4
  - These vulnerabilities have no threat value and are not useful as arsenal tools
  - Attackers with access can achieve objectives through legitimate means
- **2025-01-26:** Added internal/local DoS attack category
  - Added Category O2: Internal/Local Denial of Service (DoS) Attacks
  - Clarified that DoS requiring internal network access or affecting local, non-network-reachable software = TIER 4
  - Rationale: No real-world application - once inside, attackers want to stay silent and not disrupt
  - Internal DoS is counterproductive (draws attention, increases detection risk) and not useful in attacker toolkits
  - Exception: External DoS may have value for DDoS campaigns, but assess case-by-case
- **2025-01-26:** Added comprehensive Software Assessment requirement
  - Added STEP 0: Software Assessment (Required Before Kill Chain Analysis)
  - Requires assessment of network reachability (network-enabled vs local tool)
  - Requires assessment of deployment context (public-facing, internal, backend processing, IoT, etc.)
  - Requires assessment of execution context (privilege level, root/admin, containerized, etc.)
  - Requires assessment of application-specific context (where deployed, who has access, what it processes)
  - Critical: Software assessment information is required before kill chain analysis to correctly assess where vulnerability can be used
  - Updated assessment flow to include Software Assessment as first step
- *Future updates should be documented here with dates and rationale*

---

## Notes for AI Agents

**CRITICAL: Assessment Flow - Start with Kill Chain, Then Fine-Tune**

1. **STEP 0: Software Assessment (REQUIRED FIRST)**
   - **Network Reachability:** Is the software network-reachable? Network-enabled? Or local tool only?
   - **Deployment Context:** What is the software's application? Where is it typically deployed? (Public-facing, internal, backend processing, IoT, local tool)
   - **Execution Context:** What privilege level does it run as? (Root/admin, system/service, standard user) Is it containerized?
   - **Application-Specific Context:** If backend processing, where deployed? If network service, what protocols? If local tool, what access required?
   - **Critical:** This information is **required** before kill chain analysis. Without understanding software context, correct kill chain assessment is impossible.

2. **PRIMARY STEP: Kill Chain Applicability Assessment**
   - **Use software assessment information** to think like an attacker: "Where can I use this vulnerability? What value does it bring?"
   - **Assess attack scenario:** Can I use this for initial access? Do I need prerequisites? What can I achieve?
   - **Consider software context:** How does network reachability, deployment, and execution context affect exploitability?
   - **Determine base tier** based on kill chain utility and software context:
     - **TIER 1:** Can exploit immediately from outside, no barriers, high value (initial access, RCE, data breach), **typically public-facing or internet-exposed IoT**
     - **TIER 2:** High value but requires prerequisites (exploited/PoC but needs credentials/network access), or public-facing with barriers
     - **TIER 3:** Post-compromise utility, significant prerequisites, barriers + low impact, or **LAN/internal-only deployment** (requires network access first)
     - **TIER 4:** Low kill chain utility, theoretical, or admin-only where legitimate access suffices

2. **SECONDARY STEP: Category Fine-Tuning**
   - **After** determining base tier from kill chain assessment, apply category adjustments
   - Use categories to refine your assessment based on specific factors
   - Apply adjustments sequentially: Start with base tier from kill chain, then apply authentication adjustments, then other factors

3. **Cumulative adjustments:** Multiple factors can compound (e.g., admin-only + high complexity = significant de-prioritisation).

4. **Context matters:** Always consider the specific environment and threat model. Internal-only systems may have different priorities than internet-facing services.

5. **Evidence-based:** Prioritise empirical indicators (active exploitation, PoC availability) over theoretical severity.

6. **WAA principles:** Every adjustment should align with the Work-Averse Attacker model—minimising effort, maximising return, prioritising reliability.

7. **4-Tier System Logic:**
   - **TIER 1:** Immediate external threat, no barriers, high value (initial access, RCE, data breach)
   - **TIER 2:** High value but requires prerequisites (exploited/PoC but can't access from outside immediately, but provides high-impact gain)
   - **TIER 3:** Arsenal value, post-compromise utility, significant prerequisites, or barriers + low impact
   - **TIER 4:** Low kill chain utility, theoretical, or admin-only where legitimate access suffices

8. **Barriers/Prerequisites:** When evaluating, consider if the vulnerability can be exploited immediately from outside (TIER 1) or requires initial access/credentials/privileges (TIER 2 or TIER 3).

9. **Deployment Scenario Assessment:**
   - **Always assess common deployment patterns** before final tier assignment
   - **Public-facing software** with unauthenticated vulnerabilities = Maximum kill chain utility
   - **LAN/internal-only software** = Lower kill chain utility (requires network access first)
   - **IoT devices** = Special considerations (mass exploitation, botnet value, often exposed)
   - Consider: "If I'm an external attacker, can I reach this without network-level access?"

10. **Local Tool Assessment:**
    - **If vulnerability is in a local tool** that requires environment access:
      - **Does it enable privilege escalation?** If NO → Lower utility
      - **Does it allow code execution?** If NO → Lower utility
      - **Does it provide value beyond legitimate access?** If NO → **TIER 4** (no threat value, not useful as arsenal tool)
    - **Critical:** Local tools that require access but don't enable privilege escalation or code execution are **TIER 4** - attackers with access can achieve objectives through legitimate means

11. **DoS Attack Assessment:**
    - **If vulnerability causes Denial of Service:**
      - **Does it require internal network access?** If YES → **TIER 4** (no real-world application)
      - **Does it affect local, non-network-reachable software?** If YES → **TIER 4** (no real-world application)
      - **Can it be exploited from outside the network?** If NO → **TIER 4** (internal/local DoS)
    - **Critical:** Internal/local DoS attacks are **TIER 4** - once inside the network, attackers want to stay silent and not disrupt anything. DoS from inside is counterproductive and not useful in attacker toolkits.
    - **Exception:** External DoS (exploitable from outside) may have value for DDoS campaigns, but assess on case-by-case basis
8. **Critical Rule - Barriers + Low Impact Gain:** If a vulnerability has barriers (authentication, prerequisites, **MitM/network-level access**) AND does not provide high-impact gain (RCE, data breach, privilege escalation to admin), it should **NEVER** be TIER 1 or TIER 2, regardless of:
   - Active exploitation status
   - Public PoC availability
   - High EPSS scores
   - Mass exploitation potential
   
   **Examples of Low Impact Gain:**
   - Client-side attacks only (XSS, clickjacking)
   - Phishing facilitation
   - Content manipulation without code execution
   - **Information disclosure (view-only)** - Ability to view settings/information without modification capability
   - **Plaintext credential transmission requiring MitM** - Only enables credential interception, not direct authentication bypass
   - **Authentication bypass (view-only)** - Bypasses authentication but only allows viewing, not modifying
   - Limited information disclosure
   - Local privilege escalation (post-compromise)
   
   **Examples of Significant Barriers:**
   - Authentication requirements
   - **Man-in-the-Middle (MitM) / Network-level access requirements** - Network spoofing, ARP poisoning, compromised network infrastructure
   - User interaction requirements
   - Specific configuration requirements
   
   These belong in **TIER 3 (Arsenal Value)** or **TIER 4**, even if actively exploited or have public PoCs.

