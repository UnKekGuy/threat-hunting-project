# Week 5 - Threat Hunting Concept

Tasks from the syllabus: learn the threat hunting models, write a hunting hypothesis, build hunt queries for a SIEM and run them on real logs.

## Files

- [`scripts/hunt_powershell.py`](scripts/hunt_powershell.py) - the hunt logic in Python, the same filter as the SIEM queries below
- [`output/hunt_results.txt`](output/hunt_results.txt) - the real output of the hunt

## 1. Hunting models

| Model | Starts from | What you do | Result |
|---|---|---|---|
| Intel-driven | a report, IOCs or TTPs of a known group | turn the report into questions for your own logs | do we have this threat or not |
| Hypothesis-driven | a statement that can be proven wrong | decide what evidence should exist, query it, accept or reject the hypothesis | new detections even if nothing bad is found |
| Data-driven (anomaly) | the data itself, a baseline of normal | look for outliers: rare parents, rare hosts, new tools | finds things nobody wrote a rule for |

Main ideas I took from the SANS papers:

- Hunting is done by a human and starts from the idea that the attacker is already inside and got past automatic alerts. It is not the same as working through an alert queue or searching for one IOC.
- A hypothesis must say what behaviour, where, what evidence we expect and when we consider it false. Otherwise you can't finish the hunt.
- It works like the scientific method: hypothesis, test, result, new hypothesis.
- A hunt with no compromise found still gives results: a baseline of normal activity, missing logs, and new detection rules.

My hunt is **intel-driven + hypothesis-driven**: the intel is CISA AA23-325A from week 4, and from it I made a hypothesis.

## 2. Hypothesis

In week 4 LockBit affiliates, after getting into the network through the VPN gateway, used:

- `123.ps1`: PowerShell that decodes base64 into a DLL;
- HTA files started with `mshta.exe`, which then run PowerShell;
- batch and PowerShell scripts for everything else.

> **Hypothesis:** an attacker who got into a bank workstation or server runs PowerShell with hidden content (`-EncodedCommand`, `IEX`, `Net.WebClient`, download methods, `-ExecutionPolicy Bypass`) or starts PowerShell from `mshta.exe`. This will be visible in process creation events and in PowerShell Script Block Logging.

| Item | Value |
|---|---|
| ATT&CK | [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/), [T1027 Obfuscated Files](https://attack.mitre.org/techniques/T1027/), [T1218.005 Mshta](https://attack.mitre.org/techniques/T1218/005/) |
| Time range | last 30 days, wider around any hit |
| Logs needed | Sysmon Event ID 1, Security 4688 (with command line auditing on), PowerShell Operational 4104 |
| Extra logs for checking hits | Sysmon 3 (network), proxy / DNS, EDR process tree, logons |
| The hypothesis is false if | every hit comes from known admin scripts, SCCM/Intune or other approved tools with normal parents, and nothing else suspicious happened on the host |

## 3. Queries

### Splunk SPL

```spl
index=windows (
    (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
    OR (sourcetype="WinEventLog:Security" EventCode=4688)
    OR (sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
)
| eval image=lower(coalesce(Image, NewProcessName))
| eval parent=lower(coalesce(ParentImage, ParentProcessName))
| eval command_line=coalesce(CommandLine, ProcessCommandLine, ScriptBlockText)
| where EventCode=4104 OR match(image, "\\\\(powershell|pwsh)\\.exe$")
| eval reason=case(
    match(command_line, "(?i)(\\s[-/](enc|encodedcommand|e|ec)\\s|executionpolicy\\s+bypass|\\s-ep\\s+bypass|invoke-expression|\\biex\\b|net\\.webclient|downloadstring|downloadfile|invoke-webrequest|\\biwr\\b)"), "suspicious arguments",
    match(parent, "\\\\mshta\\.exe$"), "parent is mshta.exe")
| where isnotnull(reason)
| table _time host user EventCode reason image parent command_line
| sort 0 - _time
```

### Elastic (ES|QL)

KQL is not good here: inside quotes `*` is not a wildcard, and keyword fields are case-sensitive, so `"*powershell*"` would miss `PowerShell.exe`. ES|QL can lowercase the field first:

```esql
FROM logs-windows*
| WHERE event.code IN ("1", "4688", "4104")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, powershell.file.script_block_text))
| EVAL exe = TO_LOWER(process.executable), parent = TO_LOWER(process.parent.executable)
| WHERE event.code == "4104" OR exe RLIKE ".*\\\\(powershell|pwsh)\\.exe"
| EVAL reason = CASE(
    cmd RLIKE ".*( -enc | -encodedcommand | -e | -ec |executionpolicy bypass| -ep bypass|invoke-expression|iex|net\\.webclient|downloadstring|downloadfile|invoke-webrequest|iwr ).*", "suspicious arguments",
    parent RLIKE ".*\\\\mshta\\.exe", "parent is mshta.exe",
    null)
| WHERE reason IS NOT NULL
| KEEP @timestamp, host.name, user.name, event.code, reason, exe, parent, cmd
| SORT @timestamp DESC
```

Field names are ECS (Elastic Agent / Winlogbeat with the Windows module). For raw `winlog.event_data.*` fields the names have to be changed.

## 4. Running the hunt

I don't have a bank SIEM, so I ran the same logic on public Windows logs from [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets). These are recorded attack simulations from a lab domain `theshire.local` with Sysmon, Security and PowerShell logging on. I took three datasets:

| Dataset | What happens in it |
|---|---|
| `empire_launcher_vbs` | VBS file starts an Empire PowerShell stager (attack) |
| `cmd_mshta_vbscript_execute_psh` | `mshta.exe` runs VBScript, which starts PowerShell (attack, like LockBit HTA) |
| `psh_powershell_httplistener` | PowerShell opens an HTTP listener (attack, but no process creation events recorded) |

```
python3 scripts/hunt_powershell.py empire_launcher_vbs_*.json cmd_mshta_vbscript_execute_psh_*.json psh_powershell_httplistener_*.json
```

Result ([full output](output/hunt_results.txt)):

| Dataset | Hits | What was found |
|---|---|---|
| empire_launcher_vbs | 3 (Sysmon 1, 4688, 4104) | `powershell.exe -noP -sta -w 1 -enc SQBmACgA...` with parent `wscript.exe`. The base64 decodes to a script that turns off Script Block Logging through `cachedGroupPolicySettings` and then downloads the next stage with `Net.WebClient` + `IEX`. |
| cmd_mshta_vbscript_execute_psh | 2 (4688, Sysmon 1) | `powershell.exe -noexit -command Get-Service sysmon` with parent `mshta.exe` |
| psh_powershell_httplistener | 0 | - |

## 5. Analysis

**Empire launcher: true positive.** Everything is wrong here: PowerShell started by `wscript.exe`, hidden window (`-w 1`), encoded command, and the decoded script disables logging and downloads code. In a bank this would go straight to incident response: isolate `WORKSTATION5`, find where the VBS file came from, check the network connections.

**mshta: found only because of the second rule.** The first version of my query (only suspicious arguments) gave **0 hits** on this dataset, because the command `Get-Service sysmon` is normal. It was found only after I added "parent is mshta.exe". This is a good lesson: the attacker does not have to use `-enc`, and the parent-child relation catches what the command line does not. The command itself checks whether Sysmon is running, which is reconnaissance of defences.

**HTTP listener: 0 hits = a telemetry gap, not "clean".** This dataset has no Sysmon 1 / 4688 for the PowerShell process, so a query on process creation can't find it. A hunt result means nothing without checking that the needed logs exist.

How to check a hit before calling it an incident:

1. Decode the base64 (it's UTF-16LE) and read the script.
2. Look at the process tree: who is the parent, which user, which host.
3. Check 4104 for the full script and Sysmon 3 / DNS for network connections.
4. Compare with known admin scripts and deployment tools.
5. If it is malicious, scope the other hosts with the same command and turn the query into a scheduled detection.

Ideas from the Microsoft Sentinel hunting guide that I used: start with a clear hypothesis, change the query while you hunt (I added the mshta rule), save the results, and when the hunt finds something real, turn it into an analytics rule.

## References

1. SANS, [The Who, What, Where, When, Why and How of Effective Threat Hunting](https://www.sans.org/white-papers/who-what-where-when-why-how-effective-threat-hunting/).
2. J. Kerwin, SANS, [Applying the Scientific Method to Threat Hunting](https://www.sans.org/white-papers/39610/), 2020.
3. Microsoft Learn, [Conduct end-to-end threat hunting with hunts in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/hunts).
4. CISA, [AA23-325A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a).
5. OTRF, [Security-Datasets](https://github.com/OTRF/Security-Datasets): [Empire VBS Execution](https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-190518182022.html), [Mshta VBScript Execute PowerShell](https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-201022025808.html), [PowerShell HTTP Listener](https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-201102041306.html).
