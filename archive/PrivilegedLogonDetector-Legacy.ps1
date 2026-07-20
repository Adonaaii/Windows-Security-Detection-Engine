# ==========================
# Configuration
# ==========================

$HighThreshold = 20
$MediumThreshold = 5

# ==========================
# Retrieve Events
# ==========================

$privilegedLogons = Get-WinEvent -LogName Security |
Where-Object {$_.Id -eq 4672}

Write-Host ""
Write-Host "======================================"
Write-Host " Privileged Logon Detector"
Write-Host "======================================"

Write-Host "Privileged Logons Detected: $($privilegedLogons.Count)"

if ($privilegedLogons.Count -gt $HighThreshold)
{
    Write-Host "[HIGH] Large number of privileged logons detected. Investigation recommended."
}
elseif ($privilegedLogons.Count -gt $MediumThreshold)
{
    Write-Host "[MEDIUM] Multiple privileged logons detected."
}
else
{
    Write-Host "[LOW] Privileged logon activity appears normal."
}

Write-Host ""
Write-Host "Recent Privileged Logons"
Write-Host "========================"

foreach ($logon in $privilegedLogons)
{
    Write-Host ""
    Write-Host "Time: $($logon.TimeCreated)"
    Write-Host "Event ID: $($logon.Id)"
    Write-Host "--------------------------------"
}