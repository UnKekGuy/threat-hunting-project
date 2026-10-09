# Week 4 Report: Cyber Kill Chain Analysis & ATT&CK Mapping

## Metadata

- **Group Topic:** [Insert Your Group Topic Here]
- **Incident:** SolarWinds Orion / SUNBURST supply-chain compromise (APT29)
- **Frameworks:** Lockheed Martin Cyber Kill Chain; MITRE ATT&CK Enterprise
- **Scope note:** The Kill Chain is a linear analytical model; ATT&CK records tactics and techniques that can overlap across stages. Mappings below prioritize publicly reported SolarWinds activity and identify analytical mappings where public reporting does not establish a discrete stage.

## Cyberattack Analysis (Kill Chain)

### 1. Reconnaissance

APT29 selected high-value government and private-sector organizations and obtained credentials for use against victim environments. Public ATT&CK reporting records credential-focused activity in the campaign, while the precise pre-compromise collection methods and target-selection process are not fully public.

### 2. Weaponization

The actor developed SUNBURST, a trojanized DLL designed to fit the SolarWinds Orion update framework, and used SUNSPOT to inject malicious code into the Orion build process. The resulting malicious component was signed with SolarWinds code-signing certificates, allowing it to appear as trusted software.

### 3. Delivery

SolarWinds distributed the signed, compromised Orion updates through its normal update channel between March and June 2020. This delivery method placed the SUNBURST backdoor in customer environments without requiring a phishing attachment or direct interaction by the operator.

### 4. Exploitation

For victims that installed the affected update, the trusted software supply chain provided initial execution rather than a conventional vulnerability exploit. In follow-on activity, APT29 also exploited CVE-2020-0688 in Microsoft Exchange Control Panel to regain access to a network.

### 5. Installation

SUNBURST enabled selective follow-on deployment of second-stage tooling, including TEARDROP and Raindrop, on chosen targets. APT29 established persistence using scheduled tasks and WMI event subscriptions, including boot-triggered execution of a backdoor through `rundll32.exe`.

### 6. Command & Control

SUNBURST used DNS traffic crafted to resemble normal SolarWinds API communications and communicated with third-party servers using HTTP GET/POST. The campaign also used dynamically resolved subdomains and actor-controlled domains to route command-and-control traffic.

### 7. Actions on Objectives

APT29 used compromised credentials, forged SAML tokens, and cloud access to access targeted enterprise resources and mailboxes. It collected targeted email and local-system data, compressed stolen material into password-protected archives, and exfiltrated data over HTTPS.

## MITRE ATT&CK Mapping Table

| Kill Chain Stage | ATT&CK Tactic | Technique Name | Technique ID |
|---|---|---|---|
| Reconnaissance | Reconnaissance | Gather Victim Identity Information: Credentials | [T1589.001](https://attack.mitre.org/techniques/T1589/001/) |
| Weaponization | Resource Development | Develop Capabilities: Malware | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) |
| Weaponization | Defense Evasion | Subvert Trust Controls: Code Signing | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) |
| Delivery | Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) |
| Exploitation | Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Installation | Persistence | Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| Installation | Persistence | Event Triggered Execution: Windows Management Instrumentation Event Subscription | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) |
| Command & Control | Command and Control | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| Command & Control | Command and Control | Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| Actions on Objectives | Credential Access | Forge Web Credentials: SAML Tokens | [T1606.002](https://attack.mitre.org/techniques/T1606/002/) |
| Actions on Objectives | Collection | Email Collection: Remote Email Collection | [T1114.002](https://attack.mitre.org/techniques/T1114/002/) |
| Actions on Objectives | Exfiltration | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | [T1048.002](https://attack.mitre.org/techniques/T1048/002/) |

## Intelligence-Driven Defense Analysis

- Treat the adversary, not only the vulnerability, as a component of risk; use knowledge of the actor's capabilities, infrastructure, and objectives to anticipate future activity.
- Model intrusions as a sequence of adversary actions. Detecting or mitigating any required phase disrupts the operation before the objective is achieved.
- Map indicators and observations from each intrusion phase to specific defensive courses of action for detection, mitigation, response, and measurement.
- Link discrete intrusions into campaigns through recurring indicators, infrastructure, malware, and TTP patterns; campaign-level context produces more actionable intelligence than isolated alerts.
- Operate an iterative intelligence feedback loop: collection improves analysis, analysis directs defenses, and defensive results generate new collection requirements.
- Use threat-driven analysis to prioritize security investments and assess defensive effectiveness against the adversary's demonstrated behavior.

## Deliverable Placeholders

![Kill Chain Diagram](./images/kill_chain_map.png)

> 🎥 **Video Demo:** [Link to recording]

## References

1. Lockheed Martin, [*Intelligence-Driven Computer Network Defense: Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains*](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf).
2. MITRE ATT&CK, [SolarWinds Compromise (C0024)](https://attack.mitre.org/campaigns/C0024/).
3. MITRE ATT&CK, [SUNBURST (S0559)](https://attack.mitre.org/software/S0559/).
4. CISA, [Active Exploitation of SolarWinds Software](https://www.cisa.gov/news-events/alerts/2020/12/13/active-exploitation-solarwinds-software).
