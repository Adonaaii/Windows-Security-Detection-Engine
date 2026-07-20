<#
.SYNOPSIS
    Detects privileged logon events in Windows Security logs.

.DESCRIPTION
    Retrieves Event ID 4672 from the Windows Security log, extracts
    account and privilege information, performs a basic risk assessment,
    and displays a structured investigation report.

.NOTES
    Run PowerShell as Administrator to access the Security log.
#>

$eventId = 4672
$maximumEvents = 5

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = $eventId
    } -MaxEvents $maximumEvents -ErrorAction Stop

    if (-not $events) {
        Write-Host 'No privileged logon events were found.'
        exit
    }

    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $eventData = @{}

        foreach ($data in $xml.Event.EventData.Data) {
            $eventData[$data.Name] = $data.'#text'
        }

        $username   = $eventData['SubjectUserName']
        $domain     = $eventData['SubjectDomainName']
        $logonId    = $eventData['SubjectLogonId']
        $privileges = $eventData['PrivilegeList']

        if ($username -eq 'SYSTEM' -and $domain -eq 'NT AUTHORITY') {
            $riskLevel = 'Low'
            $recommendation = (
                'Expected Windows system activity. Review only if the timing ' +
                'or surrounding activity is unusual.'
            )
        }
        elseif ($username -like '*$') {
            $riskLevel = 'Low'
            $recommendation = (
                'Likely system or computer account activity. Confirm that it is expected.'
            )
        }
        elseif ($username -eq 'Administrator') {
            $riskLevel = 'Medium'
            $recommendation = (
                'Verify that the Administrator logon was authorised and expected.'
            )
        }
        else {
            $riskLevel = 'Medium'
            $recommendation = (
                'Review the account and confirm that the privileged logon was expected.'
            )
        }

        Write-Host ''
        Write-Host '=================================================='
        Write-Host '           PRIVILEGED LOGON DETECTED'
        Write-Host '=================================================='
        Write-Host "Time:           $($event.TimeCreated)"
        Write-Host "Event ID:       $($event.Id)"
        Write-Host "Account:        $domain\$username"
        Write-Host "Logon ID:       $logonId"
        Write-Host "Machine:        $($event.MachineName)"
        Write-Host "Risk Level:     $riskLevel"
        Write-Host ''
        Write-Host 'Privileges:'
        Write-Host $privileges
        Write-Host ''
        Write-Host 'Recommendation:'
        Write-Host $recommendation
        Write-Host ''
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)"
}