# Week 6: T1059.001 PowerShell Simulation
# Benign: the encoded command only prints a line. Same pattern as LockBit's 123.ps1
# (base64 inside PowerShell), but nothing is written to disk and nothing goes to the network.
Write-Output "[+] Executing T1059.001 (Command and Scripting Interpreter: PowerShell) Simulation..."
$cmd = "Write-Output 'ATT&CK T1059 Simulation Executed Successfully'"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
Write-Output "[+] Encoded command: $encoded"
# powershell.exe on Windows, pwsh on Linux/macOS: use the same binary that runs this script
$exe = (Get-Process -Id $PID).Path
Write-Output "[+] Child process: $exe -EncodedCommand <base64>"
& $exe -NoProfile -EncodedCommand $encoded
