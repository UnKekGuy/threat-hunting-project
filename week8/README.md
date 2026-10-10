# Week 8 - Creating a Plan to Emulate an Attacker's Action

Tasks from the syllabus: build a simple adversary emulation plan (initial access → persistence → data exfiltration) and document it with ATT&CK techniques.

This is a **planning document**, not an attack script. It describes what a red team would do in an authorized test and, for every step, what the blue team should see. The detections come from weeks 5-7. No exploit code or ready-to-run offensive commands are in this repo: the "how to run it" column only points at public, authorized tools (MITRE CALDERA, Atomic Red Team) that a lab operator runs on their own test range.

## 1. What an emulation plan is

Adversary emulation = copying the behaviour (TTPs) of one real group to test whether your defences would catch it. It is different from a normal pentest:

| Pentest | Adversary emulation |
|---|---|
| goal: find any way in | goal: act like one specific group |
| any tools | only the TTPs that group is known to use |
| answers "can we be broken in" | answers "would we detect LockBit" |

The plan is built from threat intelligence: you take a report, pull out the TTPs, and turn each one into a test. Here the report is CISA [AA23-325A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) (LockBit via Citrix Bleed), the same source as weeks 4-7.

## 2. Scope and rules (always first)

| Item | Value |
|---|---|
| Who we emulate | LockBit 3.0 affiliates, [ATT&CK Group G0032 / Software S1202](https://attack.mitre.org/software/S1202/) |
| Goal | check detection and response for a ransomware intrusion into a bank, from the VPN gateway to encryption |
| Where | isolated lab only: a few Windows VMs in a test domain with Sysmon, Security auditing and PowerShell logging, no connection to the real bank network |
| Not allowed | no real encryption of real data, no real exfiltration to the internet (exfil goes to a lab server), no test on production, written authorization before anything runs |
| Safety | every step has a cleanup action; the "encryption" step only renames/encrypts files in one throwaway folder |

> This plan is written so it can be executed **only** by the bank's own red team or a hired firm, on their own lab, with permission on paper. Running these techniques on systems you do not own is a crime.

## 3. The plan: 3 phases, mapped to ATT&CK

I follow the syllabus structure (initial access → persistence → data exfiltration) and keep it close to the real LockBit chain from week 4.

### Phase 1 - Initial access and discovery

| # | Step (behaviour) | ATT&CK | How to emulate (authorized tools) | What the blue team should see |
|---|---|---|---|---|
| 1 | Reach a vulnerable VPN gateway, use a stolen session cookie (simulated: we start with a foothold on one workstation) | [T1133](https://attack.mitre.org/techniques/T1133/) External Remote Services, [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | start the CALDERA agent on the "patient zero" VM by hand (stands in for the cookie theft) | one VPN user from two public IPs (week 4 recommendation) |
| 2 | Look around: OS, user, hosts, domain | [T1082](https://attack.mitre.org/techniques/T1082/), [T1033](https://attack.mitre.org/techniques/T1033/), [T1018](https://attack.mitre.org/techniques/T1018/), [T1087.002](https://attack.mitre.org/techniques/T1087.002/) | CALDERA abilities: *Find OS Version* (b6b105b9…), *Identify active user* (c0da588f…), *Discover local hosts* (13379ae1…), *Domain Account Discovery* (c7ec57cd…) | burst of discovery commands from one host (`whoami`, `net`, `nltest`) in a short time |

### Phase 2 - Execution, persistence, credential access

| # | Step | ATT&CK | How to emulate | What the blue team should see |
|---|---|---|---|---|
| 3 | Run an encoded PowerShell loader (like `123.ps1`) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027](https://attack.mitre.org/techniques/T1027/) | the benign script from **week 6** (`simulate_t1059.ps1`) | **week 5 hunt**: PowerShell with `-EncodedCommand` → Sysmon 1 / 4688 / 4104 |
| 4 | Persist through a scheduled task / service | [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | CALDERA *Replace a service binary* (52771610…); or `schtasks` (LockBit used `UpdateAdobeTask`) | new scheduled task / new service creation (Security 4698 / 7045) |
| 5 | Install a remote access tool | [T1219](https://attack.mitre.org/techniques/T1219/) | drop a signed RMM installer (AnyDesk) in the lab | AnyDesk/Splashtop process + service on a server that should not have it |
| 6 | Dump LSASS for credentials | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | CALDERA *Dump LSASS memory using ProcDump* (0ef4cc7b…) or the comsvcs MiniDump method | **week 7 analytic** CAR-2020-05-001: Sysmon 10 on lsass.exe with `dbghelp`/`dbgcore` in the call trace |

### Phase 3 - Lateral movement, collection, exfiltration, impact

| # | Step | ATT&CK | How to emulate | What the blue team should see |
|---|---|---|---|---|
| 7 | Move to another host with PsExec / WMI | [T1569.002](https://attack.mitre.org/techniques/T1569.002/), [T1047](https://attack.mitre.org/techniques/T1047/), [T1021.002](https://attack.mitre.org/techniques/T1021.002/) | CALDERA *Service Creation Lateral Movement* profile (service `sandsvc`) | remote service creation 7045, `psexesvc`, remote WMI process create |
| 8 | Stage and compress files | [T1074.001](https://attack.mitre.org/techniques/T1074.001/), [T1560.001](https://attack.mitre.org/techniques/T1560.001/) | CALDERA *Create local staging directory* (6469befa…) + *Compress staged directory* (300157e5…) | a `.zip`/`.7z` built from many user files by an odd process |
| 9 | Exfiltrate to a **lab** server | [T1567.002](https://attack.mitre.org/techniques/T1567.002/) / [T1041](https://attack.mitre.org/techniques/T1041/) | CALDERA *Exfil staged directory* (ea713bc4…) pointed at the lab C2, **never** a real cloud | large outbound upload from a server, to a new destination |
| 10 | Impact: stop services, "encrypt" a test folder | [T1489](https://attack.mitre.org/techniques/T1489/), [T1486](https://attack.mitre.org/techniques/T1486/) | CALDERA *Stop PowerShell processes* (134b49a3…); a safe script that only touches one throwaway folder and keeps the key | mass `taskkill` of SQL services (week 4), many files renamed in seconds |

## 4. How to run it (for the lab operator)

The usual tool for this is **MITRE CALDERA**. The operator, on their own authorized lab:

1. loads an **adversary profile** (an ordered list of the ability IDs above);
2. starts an agent on the patient-zero VM;
3. runs the profile and watches it step through the phases;
4. **collects the logs** and checks them against the week 5-7 queries;
5. runs the **cleanup** of every ability to return the lab to clean state.

The point is step 4: the plan is only useful if every technique is checked against a detection. The result is a coverage table.

## 5. Detection coverage (the real deliverable)

| Phase | Technique | Detection we have | Where | Gap |
|---|---|---|---|---|
| 1 | T1082 discovery | not yet | - | need a rule for discovery command bursts |
| 2 | T1059.001 encoded PowerShell | **yes** | week 5 ES\|QL / SPL | - |
| 2 | T1053.005 / T1543.003 persistence | partial | 4698 / 7045 exist, no query written | week 9 |
| 2 | T1003.001 LSASS dump | **yes** | week 7 CAR-2020-05-001 + CAR-2019-04-004 | Mimikatz direct-read needs the 2nd analytic |
| 3 | T1569.002 lateral movement | not yet | - | 7045 remote service rule |
| 3 | T1560.001 / T1567.002 collection + exfil | not yet | - | archive + large-upload rule |
| 3 | T1489 / T1486 impact | partial | mass taskkill idea from week 4 | encryption too late to matter, catch earlier |

Three of ten steps are covered now. The gaps become the plan for **week 9** (run these as Atomic Red Team tests and build the missing detections) and feed the ATT&CK Navigator comparison from week 6.

## 6. ATT&CK Navigator layer

[`emulation_layer.json`](emulation_layer.json) marks all techniques in this plan, coloured by detection status: green = detected (weeks 5-7), yellow = partial, red = gap. Open it in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) → Open Existing Layer. This is the picture a bank would show management: "here is the LockBit chain, here is what we would catch today, here is what we are missing."

## References

1. MITRE ATT&CK, [LockBit 3.0 (S1202)](https://attack.mitre.org/software/S1202/).
2. CISA, [AA23-325A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a).
3. MITRE, [CALDERA](https://github.com/mitre/caldera) and [stockpile abilities](https://github.com/mitre/stockpile).
4. MITRE Engenuity, [Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library).
5. Red Canary, [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).
