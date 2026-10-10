# Week 10 - Learning APT Techniques

Tasks from the syllabus: analyze the TTPs of APT29 or APT41 and map the observed techniques to ATT&CK.

## Files

- [`apt41_layer.json`](apt41_layer.json) - ATT&CK Navigator layer of APT41 techniques, with the ones we can detect (weeks 5-9) highlighted

## 1. Which group and why APT41

I picked **APT41** ([ATT&CK G0096](https://attack.mitre.org/groups/G0096/)), not APT29, because it fits the project topic best:

- APT41 is the rare group that does **both** state espionage **and** financially-motivated crime. It has targeted the **finance** sector among others.
- It uses **ransomware for impact** (T1486, with Encryptor RaaS and even BitLocker), so it overlaps directly with the LockBit chain this project studied all semester.
- This lets week 10 answer a real question for a bank: **we built detections against a ransomware crew (LockBit); would any of them also catch a state-sponsored group like APT41?**

APT41 is China-nexus, active since ~2012, also tracked as BARIUM, Winnti, Wicked Panda, Brass Typhoon.

## 2. APT vs ransomware crew

| | LockBit 3.0 (weeks 4-9) | APT41 |
|---|---|---|
| Motivation | money (ransom) | espionage **and** money |
| Model | ransomware-as-a-service, affiliates | state-sponsored + moonlighting |
| Patience | fast: in, encrypt, leave | slow: can stay for months (C0017 ran May 2021-Feb 2022) |
| Signature move | buy access / exploit a gateway, then encrypt | **supply chain compromise**: inject code into legitimately signed software (T1195.002, T1553.002) |
| Stealth | medium, noisy near the end | high: environmental keying (T1480.001), code-signing, event-log clearing |

The key difference for a defender: LockBit is loud and quick, APT41 is quiet and long. But in the middle of the intrusion they use **many of the same hands-on-keyboard techniques**, and that is where the same detections work.

## 3. APT41 TTPs mapped to ATT&CK

Grouped by tactic. Techniques **in bold** overlap with the LockBit chain this project studied in weeks 4-9 (same technique in both adversaries). The subset we wrote and tested a detection for is listed separately in section 4.

| Tactic | APT41 techniques (ATT&CK IDs) |
|---|---|
| Initial Access | T1190 Exploit Public-Facing App (ProxyLogon, Log4j), T1133 External Remote Services, T1566.001 Spearphishing Attachment, **T1195.002 Supply Chain Compromise** |
| Execution | **T1059.001 PowerShell**, T1059.003 Windows Command Shell, **T1047 WMI**, **T1569.002 Service Execution**, **T1053.005 Scheduled Task**, T1203 Exploitation for Client Execution |
| Persistence | T1547.001 Registry Run Keys, **T1543.003 Windows Service**, T1505.003 Web Shell, T1136.001 Create Account, T1542.003 Bootkit |
| Privilege Escalation | T1134 Access Token Manipulation (BADPOTATO), T1055 Process Injection |
| Defense Evasion | **T1027 Obfuscated/Encoded Files**, T1140 Deobfuscate/Decode, T1036 Masquerading, T1070.001 Clear Windows Event Logs, T1553.002 Code Signing, T1480.001 Environmental Keying |
| Credential Access | **T1003.001 LSASS**, T1003.002 SAM, T1003.003 NTDS, T1110 Brute Force, T1555.003 Browser Credentials, T1056.001 Keylogging |
| Discovery | T1082 System Info, T1083 File/Directory, T1087 Account, T1018 Remote System, T1033 System Owner/User, T1046 Network Service |
| Lateral Movement | T1021.001 RDP, **T1021.002 SMB/Admin Shares**, T1570 Lateral Tool Transfer, T1550.002 Pass the Hash |
| Collection | T1005 Local Data, **T1074.001 Local Data Staging**, **T1560 Archive Collected Data**, T1213 Data from Repositories |
| Command & Control | T1071.001 Web, T1071.004 DNS, T1105 Ingress Tool Transfer, T1090 Proxy, T1573.002 Asymmetric Crypto, T1102 Web Service |
| Exfiltration | T1041 Over C2, T1048.003 Unencrypted non-C2, **T1567.002 Exfiltration to Cloud Storage** |
| Impact | **T1486 Data Encrypted for Impact** (ransomware), T1496 Resource Hijacking (Monero mining) |

**Notable tooling:** Cobalt Strike, Mimikatz, Impacket, PowerSploit, Empire (same offensive kit as many ransomware crews), web shells China Chopper and ASPXSpy, and custom malware PlugX, ShadowPad, KEYPLUG, DUSTTRAP.

## 4. Would our detections catch APT41?

Checking the project's detections (weeks 5-9) against APT41's technique list:

| Our detection | Technique | Catches APT41? |
|---|---|---|
| week 5 encoded PowerShell | T1059.001 / T1027 | **yes** - APT41 uses PowerShell and encoded files |
| week 7 LSASS dump (CAR) | T1003.001 | **yes** - APT41 dumps LSASS with Mimikatz |
| week 9 scheduled task | T1053.005 | **yes** - in APT41's list |
| week 9 service / lateral | T1543.003 / T1569.002 | **yes** - APT41 uses service execution and SMB |

So **4 of our detections apply to APT41 too.** This is the payoff of detecting *behaviour* (TTPs) instead of indicators: an IOC-based defence tuned to LockBit (its IPs, its hashes) would catch nothing of APT41, but the behaviour-based queries carry over. This is the "Pyramid of Pain" idea from week 1 - TTPs are the hardest level for the attacker to change.

## 5. What APT41 does that we do NOT yet cover

The gaps are exactly where an APT differs from a smash-and-grab crew:

- **Supply chain compromise (T1195.002)** and **code signing abuse (T1553.002)** - the signed malicious update. Very hard to catch with endpoint logs; needs software integrity and build-pipeline controls.
- **Web shells (T1505.003)** on the public gateway - needs web server / IIS logging, which this project never collected.
- **Event log clearing (T1070.001)** - needs an alert on log-clear events (1102) and shipping logs off-host so they survive.
- **Environmental keying (T1480.001)** - malware that only runs on the target, defeating sandboxes. Needs behaviour analysis in the real environment.

For a bank these would be the next detections to build after the LockBit set.

## 6. ATT&CK Navigator layer

[`apt41_layer.json`](apt41_layer.json): APT41's techniques, green = covered by one of our tested detections (the 6 technique IDs from the 4 detections in section 4), blue = APT41 technique we do not cover yet. Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Laid next to the week 8 LockBit layer, the green squares that line up are the detections that defend against both threats at once.

## 7. Conclusion for the whole project

Over ten weeks this project went from "who attacks banks" (CTI, weeks 1-3) to a working, tested detection set against a specific ransomware chain (weeks 4-9), and this week showed that the same behaviour-based detections also cover part of a very different, state-sponsored adversary. The lesson: for a bank in Kazakhstan with limited resources, the best return is detecting the **shared TTPs in the middle of the kill chain** (PowerShell, LSASS, scheduled tasks, services, lateral movement), because both the ransomware crews and the APTs have to pass through them.

## References

1. MITRE ATT&CK, [APT41 (G0096)](https://attack.mitre.org/groups/G0096/).
2. Mandiant, [APT41: Double Dragon - A Dual Espionage and Cyber Crime Operation](https://www.mandiant.com/resources/reports/apt41-dual-espionage-and-cyber-crime-operation).
3. CrowdStrike, [Global Threat Report](https://www.crowdstrike.com/global-threat-report/).
4. MITRE ATT&CK, [Supply Chain Compromise (T1195.002)](https://attack.mitre.org/techniques/T1195/002/), [Data Encrypted for Impact (T1486)](https://attack.mitre.org/techniques/T1486/).
