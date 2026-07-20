<#
.SYNOPSIS
    Analyses recent failed Windows logon attempts.

.DESCRIPTION
    Retrieves recent Event ID 4625 entries from the Windows Security log,
    extracts relevant authentication fields, translates logon type values,
    and displays a structured investigation report.

.NOTES
    Run PowerShell as Administrator to access the Security log.
#>

$eventId = 4625
$maximumEvents = 5

$logonTypes = @{
    2  = 'Interactive'
    3  = 'Network'
    4  = 'Batch'
    5  = 'Service'
    7  = 'Unlock'
    8  = 'NetworkCleartext'
    10 = 'RemoteInteractive (RDP)'
    11 = 'CachedInteractive'
}

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = $eventId
    } -MaxEvents $maximumEvents -ErrorAction Stop

    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $eventData = @{}

        foreach ($data in $xml.Event.EventData.Data) {
            $eventData[$data.Name] = $data.'#text'
        }

        $username      = $eventData['TargetUserName']
        $domain        = $eventData['TargetDomainName']
        $ipAddress     = $eventData['IpAddress']
        $workstation   = $eventData['WorkstationName']
        $logonType     = $eventData['LogonType']
        $failureReason = $eventData['FailureReason']
        $status        = $eventData['Status']
        $subStatus     = $eventData['SubStatus']

        $logonTypeName = $logonTypes[[int]$logonType]

        if (-not $logonTypeName) {
            $logonTypeName = "Unknown ($logonType)"
        }

        $riskLevel = 'Medium'
        $recommendation = (
            'Review repeated failed logons from this account or source.'
        )

        Write-Host ''
        Write-Host '================================================'
        Write-Host '              FAILED LOGON DETECTED'
        Write-Host '================================================'
        Write-Host "Time:                 $($event.TimeCreated)"
        Write-Host "Username:             $domain\$username"
        Write-Host "IP Address:           $ipAddress"
        Write-Host "Workstation:          $workstation"
        Write-Host "Logon Type:           $logonTypeName"
        Write-Host "Failure Reason:       $failureReason"
        Write-Host "Status:               $status"
        Write-Host "Sub Status:           $subStatus"
        Write-Host "Risk Level:           $riskLevel"
        Write-Host ''
        Write-Host 'Recommendation:'
        Write-Host $recommendation
        Write-Host ''
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)"
}