# Registers Halyard as a Windows Scheduled Task that starts at logon.
#
# Written by `halyard install-service`, then run BY YOU - this script is not
# executed automatically. Creating a scheduled task is a system-wide change that
# outlives the process which made it, and that needs your own hands.
#
# A user task at logon, not a service: Halyard runs an agent as you, and a
# SYSTEM service would neither find your PATH nor your agent's credentials.
$ErrorActionPreference = 'Stop'

$taskName = 'Halyard'
$node     = '{{NODE}}'
$entry    = '{{ENTRY}}'
$workdir  = '{{WORKDIR}}'
$dataDir  = '{{DATA_DIR}}'

# -WindowStyle Hidden on a console exe still flashes a window on Windows 11,
# because the console host is created before the switch takes effect. A hidden
# task with no interactive token avoids that entirely.
$action = New-ScheduledTaskAction -Execute $node -Argument "`"$entry`" start" -WorkingDirectory $workdir
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

[Environment]::SetEnvironmentVariable('HALYARD_DATA_DIR', $dataDir, 'User')

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
    -Description 'Halyard - drive a coding agent from your phone' | Out-Null

Write-Host ""
Write-Host "  Registered scheduled task '$taskName' (starts at logon)."
Write-Host "  Start it now:  Start-ScheduledTask -TaskName $taskName"
Write-Host "  Remove it:     Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false"
Write-Host ""
