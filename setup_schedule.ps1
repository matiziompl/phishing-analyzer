$ScriptDir = $PSScriptRoot
$Action = New-ScheduledTaskAction -Execute "python" -Argument "$ScriptDir\analyzer.py --hours 24" -WorkingDirectory $ScriptDir
$Trigger = New-ScheduledTaskTrigger -Daily -At 9:00AM
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "PhishingAnalyzerGmail" -Action $Action -Trigger $Trigger -Settings $Settings -Description "Codzienna analiza e-maili pod kątem phishingu" -User $env:USERNAME
Write-Host "Zadanie harmonogramu zostało pomyślnie utworzone. Będzie uruchamiane codziennie o 9:00."
