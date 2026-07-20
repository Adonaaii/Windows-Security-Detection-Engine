<#
.SYNOPSIS
    Detects possible brute-force activity in Windows Security logs.

.DESCRIPTION
    Retrieves failed logon events with Event ID 4625, groups them by
    username, and checks whether an account generated five or more
    failed logons within a rolling 60-second window.

.NOTES
    Run PowerShell as Administrator to access the Security log.
#>

$eventId = 4625
$maximumEvents = 100
$failureThreshold = 5
$timeWindowSeconds = 60

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = $eventId
    } -MaxEvents $maximumEvents -ErrorAction Stop

    $failedLogons = foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $eventData = @{}

        foreach ($data in $xml.Event.EventData.Data) {
            $eventData[$data.Name] = $data.'#text'
        }

        [PSCustomObject]@{
            Username    = $eventData['TargetUserName']
            TimeCreated = $event.TimeCreated
            IpAddress   = $eventData['IpAddress']
        }
    }

    $alertGenerated = $false

    foreach ($userGroup in ($failedLogons | Group-Object Username)) {
        $userEvents = $userGroup.Group | Sort-Object TimeCreated

        foreach ($startingEvent in $userEvents) {
            $windowEnd = $startingEvent.TimeCreated.AddSeconds(
                $timeWindowSeconds
            )

            $eventsInWindow = $userEvents | Where-Object {
                $_.TimeCreated -ge $startingEvent.TimeCreated -and
                $_.TimeCreated -le $windowEnd
            }

            if ($eventsInWindow.Count -ge $failureThreshold) {
                $sourceAddresses = $eventsInWindow.IpAddress |
                    Where-Object { $_ -and $_ -ne '-' } |
                    Sort-Object -Unique

                Write-Host ''
                Write-Host '===================================='
                Write-Host '          HIGH RISK ALERT'
                Write-Host '===================================='
                Write-Host "User:             $($userGroup.Name)"
                Write-Host "Failed Logons:    $($eventsInWindow.Count)"
                Write-Host "Window Start:     $($startingEvent.TimeCreated)"
                Write-Host "Window End:       $windowEnd"
                Write-Host "Source IP(s):     $($sourceAddresses -join ', ')"
                Write-Host 'Detection:        Possible brute-force attack'
                Write-Host 'Recommendation:   Investigate immediately'
                Write-Host ''

                $alertGenerated = $true
                break
            }
        }
    }

    if (-not $alertGenerated) {
        Write-Host ''
        Write-Host 'No brute-force activity detected.'
        Write-Host (
            "No account reached $failureThreshold failed logons " +
            "within $timeWindowSeconds seconds."
        )
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)"
}