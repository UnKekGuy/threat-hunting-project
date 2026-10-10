# Week 7 - Using MITRE CAR

Tasks from the syllabus: select an analytic from MITRE CAR (Cyber Analytics Repository), implement it in a SIEM and map it to ATT&CK.

## Files

- [`queries/car-2020-05-001.esql`](queries/car-2020-05-001.esql) - the main analytic, MiniDump of LSASS
- [`queries/car-2019-04-004.esql`](queries/car-2019-04-004.esql) - second analytic for comparison, Mimikatz access masks
- [`queries/lsass-access-baseline.esql`](queries/lsass-access-baseline.esql) - who touches lsass.exe at all
- [`scripts/load_to_elastic.py`](scripts/load_to_elastic.py) - loads the logs into Elasticsearch
- [`scripts/run_esql.py`](scripts/run_esql.py) - runs the `.esql` files and prints the results
- [`output/load.txt`](output/load.txt), [`output/results.txt`](output/results.txt) - real output

## 1. What CAR is

CAR is MITRE's library of **analytics**. ATT&CK says *what* attackers do, CAR says *how to find it in logs*. Every analytic has:

- a hypothesis and description,
- the ATT&CK techniques it covers and how well (Low / Moderate / High),
- the data it needs (CAR data model, e.g. `process/create`),
- pseudocode plus implementations for Splunk, EQL, LogPoint, Sigma and others,
- sometimes unit tests (Atomic Red Team commands that should trigger it).

**Analytic vs detection.** An analytic is a piece of search logic based on a hypothesis. It can be noisy and needs an analyst to look at the results, which is good for hunting. A detection is an analytic that has been tuned until the false positives are low enough to raise alerts automatically. CAR-2019-04-004 below is a good example: its "Outliers" version is a hunting analytic, it is not ready to be an alert.

## 2. Which analytic and why

In week 4 (CISA AA23-325A) the LockBit affiliates, after getting in through Citrix Bleed, dumped credentials:

- `procdump` and an LSASS dump at `c:\perflogs\lsass.dmp`,
- `a.exe` injecting `a.dll` into LSASS, which dumps its memory to `a.png`,
- Mimikatz.

With the passwords from LSASS they moved on with PsExec and wmiexec. If a bank catches this step, the attack stops before encryption. So I picked:

**[CAR-2020-05-001 MiniDump of LSASS](https://car.mitre.org/analytics/CAR-2020-05-001/)**: Sysmon Event ID 10 (process access) where the target is `lsass.exe` and the call stack (`CallTrace`) goes through `dbghelp.dll` or `dbgcore.dll`. These two DLLs contain `MiniDumpWriteDump()`, which almost every dumping tool uses: procdump, Task Manager, `comsvcs.dll`, Dumpert, SafetyKatz.

The nice part is that it does not depend on the tool name or the command line. LockBit renamed its tools (`a.exe`, `servicehost.exe`), so a rule like "procdump in the command line" ([CAR-2019-07-002](https://car.mitre.org/analytics/CAR-2019-07-002/)) would miss it.

For comparison I also took **[CAR-2019-04-004 Credential Dumping via Mimikatz](https://car.mitre.org/analytics/CAR-2019-04-004/)** ("Outliers" version): lsass.exe opened with the access masks Mimikatz uses (`0x1410`, `0x1010`, `0x1438`, `0x143a`, `0x1418`).

## 3. Implementation in a SIEM

**SIEM:** Elasticsearch 9.5.5, single node on my laptop, queries in ES|QL.

**Data:** I have no bank network, so I used recorded attacks from [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (lab domain `theshire.local`, Sysmon + Security + PowerShell logs). 7 datasets, 15 121 events: 4 credential dumping attacks and 3 other attacks from week 5 as background noise.

| Dataset | What happens |
|---|---|
| `psh_lsass_memory_dump_comsvcs` | `rundll32 comsvcs.dll MiniDump 756 ...\lsass-comsvcs.dmp full`, started from PowerShell |
| `rdp_interactive_taskmanager_lsass_dump` | user in RDP: Task Manager → lsass.exe → "Create dump file" |
| `cmd_lsass_memory_dumpert_syscalls` | Outflank Dumpert (direct syscalls to avoid EDR hooks) writes `C:\Windows\Temp\dumpert.dmp` |
| `empire_mimikatz_logonpasswords` | Empire agent runs Mimikatz `sekurlsa::logonpasswords` in PowerShell memory |
| `empire_launcher_vbs`, `cmd_mshta_vbscript_execute_psh`, `psh_powershell_httplistener` | no credential dumping (noise) |

The CAR Splunk version:

```spl
index=__your_sysmon_index__ EventCode=10 TargetImage="C:\\windows\\system32\\lsass.exe"
(CallTrace="*dbghelp.dll*" OR CallTrace="*dbgcore.dll*")
| table _time host SourceProcessId SourceImage
```

My ES|QL version. I made the matching case-insensitive and on the file name only, because in the logs the path is written as `C:\windows\system32\lsass.exe` and also `C:\Windows\system32\lsass.exe`:

```esql
FROM winlogs
| WHERE EventID == 10
  AND ENDS_WITH(TO_LOWER(TargetImage), "\\lsass.exe")
  AND (TO_LOWER(CallTrace) LIKE "*dbghelp.dll*" OR TO_LOWER(CallTrace) LIKE "*dbgcore.dll*")
| KEEP @timestamp, dataset, Hostname, SourceImage, SourceProcessId, GrantedAccess
| SORT @timestamp
```

Run:

```
python3 scripts/load_to_elastic.py http://127.0.0.1:9201 <datasets>.json
python3 scripts/run_esql.py http://127.0.0.1:9201 queries/*.esql
```

## 4. Results

From [`output/results.txt`](output/results.txt):

| Dataset | CAR-2020-05-001 (MiniDump) | CAR-2019-04-004 (Mimikatz masks) |
|---|---|---|
| comsvcs.dll MiniDump | **found**: `rundll32.exe`, 0x1fffff | **found**: `rundll32.exe`, 0x1410 |
| Task Manager dump | **found**: `taskmgr.exe`, 0x1fffff | **found**: `taskmgr.exe`, 0x1410 |
| Dumpert (syscalls) | **found**: `Outflank-Dumpert.exe`, 0x1fffff | missed (it asks for 0x1fffff) |
| Mimikatz logonpasswords | missed (reads memory directly, no MiniDump) | **found**: `powershell.exe`, 0x1010 |
| 3 noise datasets | 0 | 0 |

The baseline query shows what normal access to LSASS looks like here: `svchost.exe` with `0x1000` / `0x2000` / `0x3000` (just query information). Neither analytic flagged it.

## 5. Analysis

- **CAR-2020-05-001 found 3 of 4 dumps with 0 false positives.** It even caught Dumpert, which uses direct syscalls to hide from EDR, because Dumpert still writes the file with `MiniDumpWriteDump` from `dbghelp.dll`.
- **It missed Mimikatz.** `sekurlsa::logonpasswords` does not make a dump file, it reads LSASS memory with `ReadProcessMemory`, so there is no `dbghelp` in the call stack. The second analytic covers exactly this case.
- **CAR-2019-04-004 is fragile**: it depends on the exact access mask. It missed Dumpert (0x1fffff), and Mimikatz with other options or another tool could ask for a different mask. Its own description says it is "overtuned" to Mimikatz.
- **Together they cover all 4.** One analytic is never enough for one technique. This is why CAR gives "coverage: Low" for both.
- **Process creation adds context.** The comsvcs dump is also visible in Sysmon 1 / 4688 (`rundll32 ... comsvcs.dll MiniDump ... full`, parent `powershell.exe`) and the dump file in Sysmon 11 (`lsass-comsvcs.dmp`, `dumpert.dmp`, `lsass.DMP`). A detection on `*.dmp` files created by unusual processes would be a third layer.
- **Possible false positives in a real network**: `WerFault.exe` (Windows crash reporting) and `tasklist.exe` are mentioned in CAR, plus AV/EDR agents and backup software. These should be added as exceptions by full path and signature after a baseline period, not just by name. LockBit used names like `servicehost.exe`.
- **Required logging**: none of this works without Sysmon Event ID 10 with a rule for `lsass.exe`. The default Windows logs do not have process access events. For a bank, this is the first thing to check.

## 6. ATT&CK mapping

| Analytic | Tactic | Technique | Comment |
|---|---|---|---|
| CAR-2020-05-001 | Credential Access | [T1003.001 OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) | CAR lists it as **T1003.003** (NTDS), which looks like a mistake: the analytic is about LSASS memory, not the AD database |
| CAR-2019-04-004 | Credential Access | [T1003.001 OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) | |
| (context from the comsvcs dataset) | Defense Evasion | [T1218.011 System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/) | `rundll32` running `comsvcs.dll` export `MiniDump` |
| (context from the Dumpert dataset) | Execution | [T1106 Native API](https://attack.mitre.org/techniques/T1106/) | direct syscalls |

In the LockBit chain from week 4 this is stage 7 (Actions on Objectives), right before lateral movement with PsExec (T1569.002) and wmiexec (T1047).

## References

1. MITRE, [Cyber Analytics Repository](https://car.mitre.org/) and [CAR on GitHub](https://github.com/mitre-attack/car).
2. MITRE CAR, [CAR-2020-05-001 MiniDump of LSASS](https://car.mitre.org/analytics/CAR-2020-05-001/).
3. MITRE CAR, [CAR-2019-04-004 Credential Dumping via Mimikatz](https://car.mitre.org/analytics/CAR-2019-04-004/).
4. CISA, [AA23-325A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a).
5. OTRF, [Security-Datasets](https://github.com/OTRF/Security-Datasets).
6. Elastic, [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql).
