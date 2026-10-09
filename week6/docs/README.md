# Week 6 Report: ATT&CK Framework — T1059 Simulation

## Executive Summary & Metadata

- **Group Topic:** [Insert Your Group Topic Here]
- **Focus Technique:** [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- **Focus Sub-technique:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Simulation artifact:** [`simulate_t1059.ps1`](../scripts/simulate_t1059.ps1)
- **Navigator layer:** [`attack_navigator.json`](../config/attack_navigator.json)
- **Execution status:** Not executed in this Linux workspace because no PowerShell runtime (`powershell.exe`, `powershell`, or `pwsh`) is installed. The terminal attempt and its unmodified output are retained in [`execution-log.txt`](./execution-log.txt).

## Technique Analysis: T1059

T1059 is the MITRE ATT&CK **Execution** technique for abuse of command and scripting interpreters to execute commands, scripts, or binaries. It contains platform- and interpreter-specific sub-techniques, including T1059.001 PowerShell, T1059.003 Windows Command Shell, T1059.004 Unix Shell, T1059.005 Visual Basic, T1059.006 Python, and T1059.007 JavaScript.

Adversaries use interpreters because they are commonly installed, support execution of arbitrary commands, and can be invoked from user sessions, malicious payloads, scheduled tasks, or remote services. For PowerShell, process creation logs, complete command lines, Script Block Logging (Event ID 4104), parent-process lineage, user context, and follow-on network or file activity provide the evidence required to differentiate approved administration from suspicious execution.

## Simulation Procedure

The supplied test is intentionally benign. It constructs a UTF-16LE Base64 representation of `Write-Output 'ATT&CK T1059 Simulation Executed Successfully'`, then launches a child `powershell.exe` with `-EncodedCommand`; it does not download content, change configuration, establish persistence, or make network connections.

```powershell
# From an authorized Windows test endpoint with PowerShell available
powershell.exe -ExecutionPolicy Bypass -File .\weeks\week06\scripts\simulate_t1059.ps1
```

### Required Telemetry

| Source | Event ID | Evidence |
|---|---:|---|
| Windows Security auditing | 4688 | Process creation, image, parent process, user, and command line when command-line auditing is enabled. |
| Sysmon Operational | 1 | PowerShell process creation, command line, process GUID, parent image, and parent command line. |
| PowerShell Operational | 4104 | Script-block content for the decoded simulation command when Script Block Logging is enabled. |

## Actual Terminal Output

```text
$ powershell.exe -File weeks/week06/scripts/simulate_t1059.ps1
zsh:1: command not found: powershell.exe
```

The output above is the actual result from the current workspace; no simulated success output has been recorded. Run the documented command on an authorized Windows endpoint (or a system with PowerShell installed) to produce the expected `T1059 Simulation Executed Successfully` event and collect the required telemetry.

## ATT&CK Mapping

| Observed or expected activity | ATT&CK tactic | ATT&CK technique | Mapping rationale |
|---|---|---|---|
| Launch `powershell.exe` with a command argument | Execution | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | The simulation uses the PowerShell interpreter to execute an inline command. |
| Use `-EncodedCommand` | Execution; conditional Defense Evasion | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/); [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) | Base64 command encoding is observable in process telemetry. Map T1027 only when encoding is intended to conceal content; here it is a benign visibility test. |
| Persistence | — | Not simulated | No scheduled task, service, registry run key, startup item, or other persistence mechanism is created. |
| Command and Control | — | Not simulated | The script creates no outbound connection, beacon, or remote-command channel. |

## ATT&CK Navigator Layer

[`attack_navigator.json`](../config/attack_navigator.json) is a valid ATT&CK Navigator layer for Enterprise ATT&CK. It highlights the parent T1059 technique and T1059.001 PowerShell sub-technique with a score of 100.

- Open the ATT&CK Navigator, select **Open Existing Layer**, then upload `attack_navigator.json`.
- The layer's `domain` is `enterprise-attack`; its technique IDs are ATT&CK identifiers, not local rule names.
- Scores and comments are presentation metadata. They communicate simulation coverage but do not prove adversary activity or detection efficacy.
- Use the Navigator layer to compare planned coverage with collected telemetry and to identify untested sub-techniques before expanding the exercise.

## Evidence Placeholder

![Navigator Layer](../images/navigator.png)

## References

1. MITRE ATT&CK, [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/).
2. MITRE ATT&CK, [PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/).
3. MITRE ATT&CK, [ATT&CK Navigator documentation](https://mitre-attack.github.io/attack-navigator/).
