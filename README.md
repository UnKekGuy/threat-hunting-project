# Introduction to Threat Hunting - Project

Topic: ransomware threats to the financial sector of Kazakhstan
Course: Introduction to Threat Hunting (ITH), Astana IT University, 2026-2027
Group: CS-2421, Mikhnenko Roman, Kalyshev Akhmedi

## Idea

Banks are one of the favorite targets of ransomware gangs, so I wanted to look at this topic from the Kazakhstan side. Every week I take the course topic and try it on one question: which ransomware groups can hit our financial sector and how a defender could find them.

## Progress

| Week | Topic | What was done | Folder |
|------|-------|---------------|--------|
| 1 | Cyber Threat Intelligence Fundamentals | glossary of CTI terms, threat classification | [week1](week1/) |
| 2 | Data Collection Process | OSINT collection (ransomware.live, CISA, Shodan, abuse.ch) and a map of data sources | [week2](week2/) |
| 3 | Data Processing and Exploitation | MISP deployed, 259 IOCs cleaned and imported, some filter queries | [week3](week3/) |
| 4 | The Cyber Kill Chain | LockBit 3.0 via Citrix Bleed (CISA AA23-325A, ICBC case) split into 7 stages and mapped to ATT&CK | [week4](week4/) |
| 5 | Threat Hunting Concept | hypothesis from the LockBit TTPs, Splunk and ES\|QL queries, hunt run on OTRF Security-Datasets logs | [week5](week5/) |
| 6 | ATT&CK Framework | T1059.001 PowerShell encoded-command simulation, real run, Navigator layer | [week6](week6/) |
| 7 | Using MITRE CAR | CAR-2020-05-001 (MiniDump of LSASS) and CAR-2019-04-004 in Elasticsearch ES\|QL on 15k Sysmon events, LockBit credential dumping | [week7](week7/) |
| 8 | Creating a Plan to Emulate an Attacker's Action | LockBit emulation plan (initial access → persistence → exfiltration) mapped to ATT&CK, with detection-coverage table and Navigator layer | [week8](week8/) |
| 9 | Atomic Red Team | ran schtasks/service atomic tests, built the week 8 gap detections in ES\|QL (T1053.005, T1543.003/T1569.002) | [week9](week9/) |
| 10 | Learning APT Techniques | APT41 TTPs mapped to ATT&CK, compared with LockBit, checked which project detections also catch an APT | [week10](week10/) |

## Structure

```
week1/   glossary and threat classification
week2/   collection scripts, data source map, charts
week3/   MISP setup (podman), normalization and import scripts, screenshots
week4/   Kill Chain analysis of LockBit / Citrix Bleed with ATT&CK mapping
week5/   hunting hypothesis, SIEM queries, hunt script and its output
week6/   T1059.001 simulation script, execution log, Navigator layer
week7/   CAR analytics as ES|QL, Elasticsearch loader, results
week8/   LockBit adversary emulation plan and detection-coverage layer
week9/   atomic tests for the gap techniques and their detections
week10/  APT41 TTP analysis and overlap with our detections
```

## Tools

Python 3, PyMISP, MISP (misp-docker on podman), Kali Linux, free OSINT APIs, PowerShell 7, ATT&CK Navigator, Elasticsearch (ES|QL), MITRE CAR, OTRF Security-Datasets.
