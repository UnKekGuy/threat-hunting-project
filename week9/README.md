# Week 9 - Atomic Red Team

Tasks from the syllabus: run selected atomic tests (e.g. T1059, T1003), record the results in a SIEM and analyze them.

In week 8 the emulation plan ended with a coverage table that had gaps: persistence (T1053.005, T1543.003) and lateral movement (T1569.002) had no detection written yet. This week closes those gaps with the **real Atomic Red Team tests** for those techniques: the test definitions are taken verbatim from [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) (`atomics/*.yaml` below, including the `auto_generated_guid` of every test), executed on a live Windows endpoint under Wine, and the events that run would generate feed the missing ES|QL detections.

## Files

- [`queries/det-schtasks-persistence.esql`](queries/det-schtasks-persistence.esql) - T1053.005 from the task-audit side (Security 4698)
- [`queries/det-schtasks-process.esql`](queries/det-schtasks-process.esql) - T1053.005 from the process side (Sysmon 1) — works even when task auditing is off
- [`queries/det-service-lateral.esql`](queries/det-service-lateral.esql) - T1543.003 / T1569.002 service install (Security 7045) — catches both the command-as-service flavour and the dropped-.exe flavour
- [`atomics/T1053.005.yaml`](atomics/T1053.005.yaml), [`atomics/T1543.003.yaml`](atomics/T1543.003.yaml), [`atomics/T1569.002.yaml`](atomics/T1569.002.yaml) - the atomic test definitions verbatim from redcanaryco/atomic-red-team
- [`atomics/bin/AtomicService.exe`](atomics/bin/AtomicService.exe) - the real .NET payload the T1543.003 test runs
- [`scripts/run_atomic_tests.py`](scripts/run_atomic_tests.py) - runs the three atomic tests on the Wine prefix, captures every command, rc, output and the host state
- [`scripts/load_to_elastic.py`](scripts/load_to_elastic.py), [`scripts/run_esql.py`](scripts/run_esql.py) - load the events into `winlogs` and run the `.esql` files (same as weeks 6-7)
- [`output/execution-log.txt`](output/execution-log.txt) - the full captured run (commands + rc + host state)
- [`output/events.jsonl`](output/events.jsonl) - the events produced by the run, on the 4698/7045/Sysmon schema
- [`output/results.txt`](output/results.txt) - real output

## 1. What Atomic Red Team is

Atomic Red Team (Red Canary) is a library of small, single-technique tests mapped to ATT&CK. Each test is one or few commands that perform one technique, with a cleanup. The YAML carries the ATT&CK technique id, the test name, an `auto_generated_guid` (the test id), input arguments with defaults, and an executor (`type: command_prompt` = lines you would type into Command Prompt).

The loop is: **pick a test → run it in a lab → record the logs → check the detection → fix the gap**. The important part is the last two steps; running the command alone proves nothing.

## 2. Tests chosen (the week 8 gaps)

| ATT&CK | atomic test (`auto_generated_guid` in the YAML) | what it does |
|---|---|---|
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task | `Scheduled Task Executing Base64 Encoded Commands From Registry` (e895677d-…) | writes a Base64 payload into HKCU and creates a daily task whose action decodes + IEX's it from the registry - the LockBit `UpdateAdobeTask` pattern from week 4 |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Service Install | `Service Installation CMD` (981e2942-…) | `sc.exe create` with a real `AtomicService.exe` (own process, start=auto), then `sc stop`/`sc delete` cleanup |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) Service Execution | `Execute a Command as a Service` (2382dee2-…) | `sc.exe create` whose binPath is an arbitrary command (`%COMSPEC% … powershell.exe …`), `sc start` runs it - the PsExec-style remote-exec pattern |

## 3. How it was run

Lab host: a Windows endpoint under Wine (`WINEPREFIX=/home/unkek/wine-atomic-lab`, host `MASHYNACACHY\unkek`) — real Windows userland: `schtasks.exe`, `sc.exe`, `cmd.exe`, `reg.exe` and the .NET runtime that runs the atomic payload. `scripts/run_atomic_tests.py` reads the real test definitions from `atomics/*.yaml`, substitutes the `input_arguments` (defaults, plus two documented overrides), executes each executor line exactly the way `command_prompt` would type it into `cmd` — `wine cmd.exe /d /s /c <line>` — and records for every line: the exact command, return code, stdout, stderr and a UTC timestamp. After every test it captures the real resulting state (`schtasks /query`, `reg query` of the HKCU payload key, `sc query`, the SCM registry `ImagePath`) and then runs the atomic test's own `cleanup_command` lines.

Everything in [`output/execution-log.txt`](output/execution-log.txt) is captured, not written.

## 4. What is real, what is synthetic (honestly)

Wine is a real Windows userland, but it is not a domain-joined endpoint with the Task Scheduler service and the event log, so per event:

- **T1543.003 — the most real one.** `sc.exe create` returns rc=0, the service really appears in the SCM database: `reg query` of `HKLM\SYSTEM\CurrentControlSet\Services\AtomicTestService_CMD` shows the real `ImagePath "C:\atomic\AtomicService.exe"` (payload actually deployed from `atomics/bin/`), `sc query` shows `STATE : 4 RUNNING`. The 7045 event is **derived from that real SCM state** (`synthetic_from: "scm-registry"`) — Wine does not keep an event log, so the 7045 record itself is reconstructed, but with fields that were read back from the host, not invented.
- **T1569.002 — real service, stubbed payload interpreter.** `sc.exe create`/`start` work (rc=0 / the start returns rc=2 for the same reason the atomic test itself describes in its own `description`: the service reports a bad exit even when code runs), the real `ImagePath` with the command was read back from the SCM registry, and the cleanup `del C:\art-marker.txt` ran. But Wine's `powershell.exe` is a mono stub — it exits 0 without executing anything, so the marker file the command was supposed to create **did not appear** (`MarkerFound: false` in the event, verified after cleanup). `synthetic_from: "scm-registry+marker"`.
- **T1053.005 — command really ran, task did not persist.** The HKCU payload key was really written (`reg add` rc=0, read back), but Wine's Task Scheduler service is not a full one: `schtasks /Create` returns rc=1 and the created task is not even visible to its own `schtasks /query` — the classic not-persisted-in-Wine limitation, both visible in the execution log. The 4698 event is therefore **what Windows would have emitted** for that same `schtasks /Create` command (fields carried from the command line), flagged `synthetic_from: "task-not-persisted-in-wine"`. The process-creation record (Sysmon 1, EventID 1) for the `schtasks.exe` process is derived the same way — the process really started, the record is what a Sysmon host would have logged.

Event ids follow the real Windows schema: 4698 (Task Scheduler), 7045 (SCM service install), 1 (Sysmon process creation). Every event carries the `dataset` field (`atomic-T*`) that ties it back to the atomic test, same as the OTRF datasets in weeks 6-7.

## 5. Loading and detection

```
python3 scripts/load_to_elastic.py http://127.0.0.1:9201 output/events.jsonl
python3 scripts/run_esql.py     http://127.0.0.1:9201 queries/*.esql
```

Same house setup as weeks 6-7: ES 9.x, single node, `winlogs` index, `.esql` via `POST /_query?format=json`.

Results (verbatim in [`output/results.txt`](output/results.txt)): the index holds the 4 events; `det-schtasks-persistence.esql` and `det-schtasks-process.esql` each return the T1053.005 event from both sides (task audit + process), and `det-service-lateral.esql` returns **both** 7045 events — `ARTService` with the `%COMSPEC% … powershell.exe` command as its ImagePath (T1569.002) and `AtomicTestService_CMD` with `C:\atomic\AtomicService.exe` outside the `c:\windows` trees (T1543.003).

### The 7045 rule, and why it is two disjunctions

The week 8 table asked for "the 7045 remote service rule" for both techniques together, and both produce a 7045, but with different shapes — so the rule has two OR'ed conditions:

1. **command-as-service**: `ImagePath` contains `powershell*`/`cmd*`/`cscript*`/`%comspec%*` — something that is a shell being asked to run code (the T1569.002 / PsExec pattern);
2. **dropped-payload service**: `ImagePath` ends with `.exe` **and** is not under `c:\windows\` — a service whose binary lives outside the OS image (the T1543.003 / `AtomicService.exe` pattern, the same thing a real bank runs against the `C:\ProgramData\*` or `C:\Users\Public\*` drops).

On a noisy production index this rule over-fires on every legitimate 3rd-party service install, which is the point of a first-cut 7045 alert: it tells the analyst "a service just started running something — look at the ImagePath", and the analyst judges how bad it is. Narrowing it (`NOT LIKE` for known-good binary directories, `User` != `NT AUTHORITY\SYSTEM` exclusions) is the follow-up that each bank does on the rule.

## 6. Detection gaps this week closed (week 8 → week 9)

| week 8 gap row | now | detection |
|---|---|---|
| T1053.005 "no query written" (4698 side) | **closed** | `det-schtasks-persistence.esql` (4698) + `det-schtasks-process.esql` (Sysmon 1 fallback) |
| T1543.003 persistence (7045 side) | **closed** | `det-service-lateral.esql`, branch 2 |
| T1569.002 "7045 remote service rule" | **closed** | `det-service-lateral.esql`, branch 1 |

Still open from the week 8 table (T1082 discovery, T1003.001 Mimikatz direct-read, the T1560/T1567 collection+exfil, T1489/T1486 impact): not this week's scope.

## References

1. MITRE ATT&CK — [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1569.002](https://attack.mitre.org/techniques/T1569/002/).
2. Red Canary, [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — test definitions (`atomics/T*.yaml`) and the `AtomicService.exe` payload, used here verbatim.
3. Microsoft, Security event 4698 (Scheduled Task Operation) and 7045 (SCM service install), Sysmon 1 (Process creation).
4. Week 4 (`UpdateAdobeTask` / PsExec LockBit patterns), week 8 `emulation_layer.json` (the gap rows this week closes).
