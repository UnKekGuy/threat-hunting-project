# Week 6 - ATT&CK Framework

Tasks from the syllabus: study the structure of MITRE ATT&CK, pick one technique, simulate it safely, map it and show it in ATT&CK Navigator.

## Files

- [`scripts/simulate_t1059.ps1`](scripts/simulate_t1059.ps1) - safe simulation of T1059.001
- [`output/execution-log.txt`](output/execution-log.txt) - the real terminal output of the run
- [`attack_navigator_layer.json`](attack_navigator_layer.json) - layer for ATT&CK Navigator

## 1. How ATT&CK is built

- **Tactics** are the "why": the goal of the attacker at a step (Initial Access, Execution, Persistence ... Impact). Enterprise ATT&CK has 14.
- **Techniques** are the "how": the way to reach the goal, e.g. T1059 Command and Scripting Interpreter.
- **Sub-techniques** are a more exact version: T1059.001 PowerShell, T1059.003 Windows Command Shell, T1059.004 Unix Shell, T1059.005 Visual Basic, T1059.006 Python, T1059.007 JavaScript.
- **Procedures** are what a real group did, e.g. LockBit affiliates running `123.ps1`.
- Every technique page also has **Detection** (which data sources show it) and **Mitigations**.

## 2. Why T1059.001 PowerShell

It connects to the previous weeks:

- in week 4 LockBit used `123.ps1`, a PowerShell script with base64 inside that writes and starts `adobelib.dll`;
- in week 5 I hunted for exactly this kind of PowerShell.

Attackers like PowerShell because it is on every Windows machine, it is trusted, it can download and run code in memory, and admins use it every day, so it is hard to tell bad use from normal use. What helps: process creation logs with the full command line (4688 / Sysmon 1), Script Block Logging (4104), the parent process and the network activity after it.

## 3. Simulation

The script does the same trick as an attacker, but harmless: it encodes a command in base64 (UTF-16LE, like PowerShell expects) and starts a **new PowerShell process** with `-EncodedCommand`. The encoded command only prints one line. Nothing is downloaded, written to disk or changed.

```powershell
$cmd = "Write-Output 'ATT&CK T1059 Simulation Executed Successfully'"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
$exe = (Get-Process -Id $PID).Path   # powershell.exe on Windows, pwsh on Linux
& $exe -NoProfile -EncodedCommand $encoded
```

I ran it with PowerShell 7.6.6 on Linux:

```text
$ pwsh -NoProfile -File week6/scripts/simulate_t1059.ps1
[+] Executing T1059.001 (Command and Scripting Interpreter: PowerShell) Simulation...
[+] Encoded command: VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEEAVABUACYAQwBLACAAVAAxADAANQA5ACAAUwBpAG0AdQBsAGEAdABpAG8AbgAgAEUAeABlAGMAdQB0AGUAZAAgAFMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACcA
[+] Child process: .../pwsh/pwsh -EncodedCommand <base64>
ATT&CK T1059 Simulation Executed Successfully
exit code: 0
```

Full output with versions: [`output/execution-log.txt`](output/execution-log.txt).

The last line is printed by the child process from the decoded command, so the encoded execution really worked.

**Limitation:** on Linux there is no Sysmon, 4688 or 4104, so I could not collect Windows telemetry here. On a Windows test machine the same run should produce:

| Log | Event ID | What we would see |
|---|---:|---|
| Security | 4688 | new `powershell.exe` with `-EncodedCommand VwByAG...` in the command line (needs command line auditing) |
| Sysmon | 1 | the same plus the parent `powershell.exe` and the process GUID |
| PowerShell Operational | 4104 | the decoded text `Write-Output 'ATT&CK T1059 ...'` (needs Script Block Logging) |

The 4688 / Sysmon 1 event matches the week 5 hunt query (`-encodedcommand` in the command line), so the simulation can also be used to test that query.

## 4. ATT&CK mapping

| What happens | Tactic | Technique | Comment |
|---|---|---|---|
| PowerShell runs a command | Execution | [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) | the main technique |
| The command is passed as base64 | Defense Evasion | [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) | here only to test logging; in `123.ps1` it really hides the DLL |
| Persistence, C2, credential access | - | not simulated | the script does not create tasks, services, connections or touch credentials |

## 5. ATT&CK Navigator

[`attack_navigator_layer.json`](attack_navigator_layer.json) marks T1059.001 (blue) and T1027 (yellow) in Enterprise ATT&CK, Windows platform.

To open it: go to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), choose **Open Existing Layer** → **Upload from local** and pick the file.

The layer shows what we simulated, not what we can detect. The next step would be a second layer with the techniques from week 4 (the whole LockBit chain) and to compare it with this one: everything that is in the LockBit layer but not tested yet is a gap. This is what weeks 8 and 9 (emulation plan and Atomic Red Team) are for.

## References

1. MITRE ATT&CK, [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/).
2. MITRE ATT&CK, [PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/).
3. MITRE ATT&CK, [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
4. CISA, [AA23-325A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) (`123.ps1` procedure).
