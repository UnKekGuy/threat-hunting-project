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

## Structure

```
week1/   glossary and threat classification
week2/   collection scripts, data source map, charts
week3/   MISP setup (podman), normalization and import scripts, screenshots
```

## Tools

Python 3, PyMISP, MISP (misp-docker on podman), Kali Linux, free OSINT APIs.
