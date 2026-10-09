# Week 6 T1059.001 Simulation Execution Log

- **Date:** 2026-10-09
- **Host environment:** Linux shell
- **Simulation:** `weeks/week06/scripts/simulate_t1059.ps1`
- **Safety:** The payload only writes a confirmation string. It performs no network access, file modification, persistence, or privilege change.

## Runtime Result

PowerShell (`pwsh`/`powershell`) was not installed in the execution environment. The encoded payload was therefore generated and decoded in Bash to validate the exact command and expected output without executing a Windows shell.

```text
[+] Executing T1059.001 (Command and Scripting Interpreter: PowerShell) Simulation...
Write-Output 'ATT&CK T1059 Simulation Executed Successfully'
ATT&CK T1059 Simulation Executed Successfully
VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEEAVABUACYAQwBLACAAVAAxADAANQA5ACAAUwBpAG0AdQBsAGEAdABpAG8AbgAgAEUAeABlAGMAdQB0AGUAZAAgAFMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACcA
```

## Telemetry to Collect on a Windows Test Endpoint

- Security Event ID 4688: process creation for `powershell.exe` and its encoded command line.
- Sysmon Event ID 1: process image, command line, parent image, process GUID, and user context.
- PowerShell Operational Event ID 4104: decoded script-block content, if Script Block Logging is enabled.

## ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | `powershell.exe -EncodedCommand <Base64>` |
| Defense Evasion (conditional) | [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) | Base64-encoded command-line argument; used here solely to validate telemetry. |
