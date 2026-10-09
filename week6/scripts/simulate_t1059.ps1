# Week 6: T1059.001 PowerShell Simulation
Write-Output "[+] Executing T1059.001 (Command and Scripting Interpreter: PowerShell) Simulation..."
$cmd = "Write-Output 'ATT&CK T1059 Simulation Executed Successfully'"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $encoded
