$failedLogons = Get-WinEvent -LogName Security |
Where-Object {$_.Id -eq 4625}

Write-Host ""
Write-Host "==============================="
Write-Host " Failed Logon Analysis"
Write-Host "==============================="

Write-Host "Failed Logons Detected: $($failedLogons.Count)"

if ($failedLogons.Count -gt 5)
{
    Write-Host "[HIGH] Possible brute-force activity detected."
}
elseif ($failedLogons.Count -gt 2)
{
    Write-Host "[MEDIUM] Multiple failed logons detected. Investigation recommended."
}
else
{
    Write-Host "[LOW] Failed logon activity appears normal."
}

Write-Host ""
Write-Host "Recent Failed Logons"
Write-Host "-----------------"

foreach ($event in $failedLogons)
{
    Write-Host ""
    Write-Host "Time: $($event.TimeCreated)"
    Write-Host "Event ID: $($event.Id)"
}