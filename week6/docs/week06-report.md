# Week 6: ATT&CK Framework — T1059.001 Simulation

## Metadata

- **Group Topic:** [Insert Your Group Topic Here]
- **Focus Technique:** [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- **Simulated Sub-technique:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Script:** [`../scripts/simulate_t1059.ps1`](../scripts/simulate_t1059.ps1)
- **Navigator layer:** [`../config/attack_navigator_layer.json`](../config/attack_navigator_layer.json)

## Technique Analysis

T1059 covers adversary use of command and scripting interpreters to execute commands, scripts, and binaries. T1059.001 specifically covers PowerShell; common telemetry sources are Windows Security Event ID 4688, Sysmon Event ID 1, and PowerShell Operational Event ID 4104.

## Simulation

The script creates a UTF-16LE Base64-encoded PowerShell command that writes a success string. It has no network, persistence, discovery, credential-access, file-write, or privilege-escalation behavior.

| Observed behavior | ATT&CK mapping | Required validation evidence |
|---|---|---|
| `powershell.exe -EncodedCommand <Base64>` | Execution: [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | 4688 or Sysmon 1 with image, command line, parent image, user, host, and process identifiers. |
| Base64 command argument | Conditional Defense Evasion: [T1027](https://attack.mitre.org/techniques/T1027/) | 4104 decoded content and the original process command line. Encoding is used only for benign test coverage. |

## Execution Result

Native PowerShell was not available in the Linux execution environment. Bash generated and decoded the exact UTF-16LE Base64 payload and produced the expected benign output; see [execution-log.md](execution-log.md).

## References

1. MITRE ATT&CK, [Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/).
2. MITRE ATT&CK, [PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/).
3. MITRE ATT&CK, [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
