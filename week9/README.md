# Week 9 - Atomic Red Team

Tasks from the syllabus: run selected atomic tests (e.g. T1059, T1003), record the results in a SIEM and analyze them.

In week 8 the emulation plan ended with a coverage table that had gaps: persistence (T1053.005, T1543.003) and lateral movement (T1569.002) had no detection written yet. This week closes those gaps: pick the matching atomic tests, run them (as recorded datasets), and build the missing detections.

## Files

- [`queries/det-schtasks-persistence.esql`](queries/det-schtasks-persistence.esql) - T1053.005 from the task-audit side (4698)
- [`queries/det-schtasks-process.esql`](queries/det-schtasks-process.esql) - T1053.005 from the process side (Sysmon 1 / 4688)
- [`queries/det-service-lateral.esql`](queries/det-service-lateral.esql) - T1543.003 / T1569.002 service install (7045)
- [`output/results.txt`](output/results.txt) - real output

## 1. What Atomic Red Team is

Atomic Red Team (Red Canary) is a library of small, single-technique tests mapped to ATT&CK. Each test is one command that performs one technique, with a cleanup. You run a test, then check if your logging and your detections caught it. It is the fast way to answer "would we see T1053.005?" without a full CALDERA operation.

The loop is: **pick a test → run it in a lab → record the logs → check the detection → fix the gap**. The important part is the last two steps, not just running the command.

## 2. Tests chosen (the week 8 gaps)

| ATT&CK | Atomic-style test | LockBit link (week 4) |
|---|---|---|
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task | create a task that runs PowerShell at logon | `UpdateAdobeTask` for persistence |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Windows Service / [T1569.002](https://attack.mitre.org/techniques/T1569/002/) Service Execution | install a service whose binary is PowerShell, used to run code on a remote host | PsExec-style lateral movement |

## 3. Run and record

Same setup as week 7: Elasticsearch 9.5.5, ES|QL. I do not have a Windows lab to run live atomic tests, so I used the **recorded** equivalents from [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (these are exactly recorded atomic simulations in a lab domain, with full Sysmon + Security logging):

| Dataset | Technique | What happens |
|---|---|---|
| `empire_schtasks_creation_execution_elevated_user` | T1053.005 | `schtasks /Create /SC ONLOGON /TN MordorElevated /TR "powershell ... IEX(...FromBase64String...)"` |
| `empire_psexec_dcerpc_tcp_svcctl` | T1543.003 / T1569.002 | a service `Updater` is installed on a second host, its binary is `%COMSPEC% /C start /b powershell -enc ...` |

They were loaded into the same `winlogs` index with the week 7 loader (now 9 datasets, ~79k events).

## 4. The detections and what they caught

From [`output/results.txt`](output/results.txt):

**Scheduled task, audit side (4698):**

```esql
FROM winlogs
| WHERE EventID == 4698
  AND (TO_LOWER(TaskContent) LIKE "*powershell*" OR TO_LOWER(TaskContent) LIKE "*-enc*"
    OR TO_LOWER(TaskContent) LIKE "*iex*" OR TO_LOWER(TaskContent) LIKE "*frombase64string*")
```

→ 1 hit: task `\MordorElevated`, created by user `pgustavo` on `WORKSTATION5`. The task content runs PowerShell with `IEX(...FromBase64String(...))`, pulling the payload from a registry key.

**Scheduled task, process side (Sysmon 1 / 4688):** → 2 hits. The same `schtasks.exe /Create ... /TR "powershell ..."` process appears in two log sources: Sysmon Event ID 1 and Security Event ID 4688. The parent PowerShell is context in the Sysmon row, not a second matching process. This query matters because task auditing (4698) is often off, while process logging is usually on. Two angles on the same technique.

**Service install (7045):**

```esql
FROM winlogs
| WHERE EventID == 7045
  AND (TO_LOWER(ImagePath) LIKE "*powershell*" OR TO_LOWER(ImagePath) LIKE "*cmd*"
    OR TO_LOWER(ImagePath) LIKE "*-enc*" OR TO_LOWER(ImagePath) LIKE "*%comspec%*")
```

→ 1 hit: service `Updater` on `WORKSTATION6`, ImagePath `%COMSPEC% /C start /b ... powershell -noP -sta -w 1 -enc <base64>`. A normal service points at a real `.exe`; a service that launches an encoded PowerShell one-liner is almost always an attack (PsExec, Empire, Metasploit all do this).

## 5. Analysis

- **All three gaps are now covered.** Each test produced a clear hit and the queries had no false positives on the other 7 datasets.
- **Two data sources per technique is better than one.** For the scheduled task I wrote both a 4698 query and a process query. If one log is missing on a host, the other still fires. This is the same lesson as week 7 (two analytics for LSASS).
- **The content matters, not the name.** The task name `MordorElevated` and the service name `Updater` look harmless. The queries key on the *action* (PowerShell + encoded command), not the name, so renaming does not help the attacker. LockBit renamed everything (`UpdateAdobeTask`, `servicehost.exe`).
- **False positives to expect in a real bank:** software deployment (SCCM, Intune), backup agents and some installers also create tasks and services that call scripts. These should be allowlisted by the known path/publisher after a baseline, not by name.
- **Logging requirements:** 4698 needs the "Audit Other Object Access Events" policy; 7045 is in the System log by default; the process queries need command-line auditing or Sysmon. A bank should confirm all three are on and shipped to the SIEM.

## 6. Updated coverage (vs week 8)

| Technique | Week 8 | Now |
|---|---|---|
| T1059.001 encoded PowerShell | detected (wk5) | detected |
| T1003.001 LSASS dump | detected (wk7) | detected |
| T1053.005 scheduled task | gap | **detected (this week)** |
| T1543.003 / T1569.002 service / lateral | gap | **detected (this week)** |
| T1560.001 / T1567.002 collection + exfil | gap | still a gap |
| T1082 discovery burst | gap | still a gap |

Four of the plan's techniques are now covered with tested queries. The remaining gaps (data staging/exfil and discovery bursts) are the next iteration.

## References

1. Red Canary, [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) and [the wiki](https://github.com/redcanaryco/atomic-red-team/wiki).
2. OTRF, [Security-Datasets](https://github.com/OTRF/Security-Datasets).
3. CISA, [AA23-325A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a).
4. MITRE ATT&CK, [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/).

## Reproducible Atomic-linked local lab

The [local lab](local_lab/README.md) pins official Atomic Red Team YAML metadata, validates two concrete test GUIDs against three detections, and replays all nine OTRF recorded datasets into local Elasticsearch. It includes 20 checks, source/data hashes, and [a Russian defense guide](local_lab/docs/DEFENSE_GUIDE.md) (also DOCX/PDF).

Important: this is recorded-equivalent validation. No live Atomic executor, prerequisite or cleanup commands were run. The report preserves the distinction between metadata validation, predicate checks and observed OTRF results. See [the Atomic coverage report](local_lab/output/atomic-coverage.txt) for limitations.
