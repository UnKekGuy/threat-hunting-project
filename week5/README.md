# Week 5 Report: Threat Hunting Scenario & Query Execution

## Metadata

- **Group Topic:** [Insert Your Group Topic Here]
- **Hunt type:** Hypothesis-driven endpoint hunt
- **Target behavior:** Suspicious PowerShell execution
- **ATT&CK coverage:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))

## Threat Hunting Methodology & Models

| Model | Starting point | Method | Outcome |
|---|---|---|---|
| Intel-driven | Relevant threat intelligence: actor reporting, campaigns, malware, IOCs, or ATT&CK TTPs | Convert intelligence into environment-specific questions; search historical and current telemetry for the reported behavior and related artifacts. | Determines exposure to a known threat and produces detections or collection requirements from validated observations. |
| Hypothesis-driven | A falsifiable statement derived from intelligence, environmental knowledge, or an observed anomaly | Define expected observable evidence, query the required telemetry, investigate positives, and accept, reject, or refine the hypothesis. | Determines whether a plausible adversary behavior occurred and improves analytic coverage even when no malicious activity is found. |

- SANS threat-hunting principles treat hunting as a focused, iterative, human-led activity for finding adversaries that have evaded automated detection; it is not an alert queue or a one-time IOC search.
- A useful hypothesis specifies the suspected behavior, affected scope, evidence expected in telemetry, and a falsification condition. Repeatable workflows, explicit evidence, and avoidance of analytical anchoring make results defensible.
- *Practical Threat Hunting* (P. Smith) emphasizes turning attacker tradecraft into observable behaviors, baselining normal activity before labeling anomalies, and iteratively converting validated hunt logic into durable detections.
- Hunt outputs include confirmed incidents, benign-use baselines and allowlists, telemetry gaps, and detection-engineering requirements; a hunt with no confirmed compromise still creates measurable defensive value.

## Hypothesis-Driven Hunting Scenario

### Hypothesis

> An adversary or unauthorized tool is using `powershell.exe` or `pwsh.exe` with obfuscation or download-and-execute behavior to evade controls and retrieve or execute payloads. Affected endpoints will show PowerShell process creation or Script Block Logging containing encoded-command switches, execution-policy bypasses, `Invoke-Expression`, `Net.WebClient`, or download methods, and may show a suspicious parent process or network connection.

### Scope and Expected Evidence

| Item | Requirement |
|---|---|
| Time range | Start with the previous 30 days; expand around validated hits according to log retention. |
| Endpoint process telemetry | Windows Security Event ID 4688 and Sysmon Event ID 1, with full command line, image, parent image, user, host, process ID, and parent process ID. |
| PowerShell telemetry | PowerShell Operational Event ID 4104 (Script Block Logging); optionally Event IDs 4103 and 400/403 for module and engine context. |
| Corroboration | Sysmon Event ID 3, proxy/DNS logs, EDR process tree, file creation, AMSI events, and authentication logs. |
| Expected suspicious patterns | `-enc`/`-EncodedCommand`, `-ExecutionPolicy Bypass`/`-ep bypass`, `Invoke-Expression`/`IEX`, `System.Net.WebClient`, `DownloadString`, `DownloadFile`, `Invoke-WebRequest`/`iwr`. |
| Falsification condition | All hits are attributable to approved automation, signed management scripts, known administrators, and expected parent processes; no corroborating anomalous execution or network activity exists. |

## SIEM Hunt Queries (Splunk & ELK/KQL)

### Splunk SPL

```spl
index=windows (
    (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
    OR (sourcetype="WinEventLog:Security" EventCode=4688)
    OR (sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
)
| eval image=lower(coalesce(Image, NewProcessName))
| eval command_line=lower(coalesce(CommandLine, ProcessCommandLine, ScriptBlockText))
| where match(image, "\\\\(powershell|pwsh)\\.exe$") OR match(command_line, "(?i)\\b(powershell|pwsh)(\\.exe)?\\b")
| where match(command_line, "(?i)((^|\\s)(-|/)(enc|encodedcommand|ep|executionpolicy)\\b|(executionpolicy\\s+bypass|\\bep\\s+bypass\\b|invoke-expression|\\biex\\b|system\\.net\\.webclient|downloadstring|downloadfile|invoke-webrequest|\\biwr\\b))")
| table _time host user EventCode image command_line ParentImage ParentProcessName ProcessId ParentProcessId ScriptBlockId
| sort 0 - _time
```

**Logic:** The search selects Sysmon process creation, Windows process creation, and PowerShell script-block events, normalizes alternative field names with `coalesce`, then filters for PowerShell plus obfuscation, policy-bypass, or download-cradle strings. Adapt `index`, `sourcetype`, and field aliases to the Splunk Windows add-on or CIM normalization used by the deployment.

### ELK / Kibana Query Language (KQL)

```kql
winlog.event_id : (1 or 4688 or 4104) and
(
  winlog.event_data.Image : "*\\powershell.exe" or
  winlog.event_data.Image : "*\\pwsh.exe" or
  winlog.event_data.NewProcessName : "*\\powershell.exe" or
  winlog.event_data.NewProcessName : "*\\pwsh.exe" or
  winlog.event_data.CommandLine : "*powershell*" or
  winlog.event_data.ScriptBlockText : "*powershell*"
) and
(
  winlog.event_data.CommandLine : ("*-enc *" or "*-encodedcommand *" or "*-executionpolicy bypass*" or "*-ep bypass*" or "*invoke-expression*" or "*iex *" or "*system.net.webclient*" or "*downloadstring*" or "*downloadfile*" or "*invoke-webrequest*" or "*iwr *") or
  winlog.event_data.ScriptBlockText : ("*-enc *" or "*-encodedcommand *" or "*-executionpolicy bypass*" or "*-ep bypass*" or "*invoke-expression*" or "*iex *" or "*system.net.webclient*" or "*downloadstring*" or "*downloadfile*" or "*invoke-webrequest*" or "*iwr *")
)
```

**Logic:** This KQL query targets the raw Winlogbeat/Elastic Agent Windows fields for the same three event IDs, requiring PowerShell evidence and at least one suspicious argument or script token. If the pipeline maps Windows events to ECS, replace `winlog.event_data.Image`, `CommandLine`, and `ScriptBlockText` with the deployment's `process.executable`, `process.command_line`, and PowerShell script-block field; verify field names in Discover before execution.

## Findings Analysis & Recommended Reading Takeaways

### Validate Hits vs. False Positives

1. Decode Base64 supplied to `-EncodedCommand` using UTF-16LE first; preserve the original event, decoded text, analyst timestamp, and hash as evidence.
2. Reconstruct the process tree and verify the parent process, initiating user, integrity level, host role, signed binary status, and prevalence across the environment.
3. Review Event ID 4104 and AMSI/EDR telemetry for the complete script, not only the command line; inspect child processes, dropped files, persistence, and outbound DNS/HTTP connections.
4. Compare the execution against approved management tools, scheduled tasks, software-deployment systems, script repositories, change records, and known administrative users.
5. Escalate hits with an untrusted parent, remote payload retrieval, obfuscated content, unusual account/host pairing, or follow-on credential access/persistence. For confirmed or unresolved malicious behavior, scope affected hosts and identities, contain according to incident-response procedures, and convert the validated logic into a monitored detection.

### Microsoft Threat Hunting Guide Takeaways

- Start with a clear, testable hypothesis; Microsoft Sentinel supports hunts based on suspicious behavior, new threat campaigns, and detection gaps.
- Select and iteratively refine queries as evidence is collected rather than treating the initial query as final.
- Preserve hunt results and bookmarks, correlate entities and evidence, and create an incident or detection rule when the hunt exposes actionable malicious activity.
- Use MITRE ATT&CK mapping to identify coverage gaps and to prioritize additional hunting queries and data collection.
- Treat negative results as feedback: document the scope searched, telemetry quality, limitations, and the next collection or detection improvement.

## Deliverable Placeholders

![Splunk Query Execution](./images/splunk_hunt_results.png)

> 🎥 **Video Walkthrough:** [Link to demo recording]

## References

1. SANS Institute, [*The Who, What, Where, When, Why and How of Effective Threat Hunting*](https://www.sans.org/white-papers/who-what-where-when-why-how-effective-threat-hunting/).
2. SANS Institute, [*Applying the Scientific Method to Threat Hunting*](https://www.sans.org/white-papers/39610/).
3. Microsoft Learn, [Conduct end-to-end threat hunting with hunts in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/hunts).
4. P. Smith, *Practical Threat Hunting* (recommended reading).
