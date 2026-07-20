<#
.SYNOPSIS
    Monitors the status of critical Windows services.

.DESCRIPTION
    Checks a predefined list of security and infrastructure services
    and reports whether each service is running or stopped. The script
    provides an overall system health status and risk level.

.NOTES
    Some services may not be available on every Windows system.
#>

$criticalServices = @(
    'EventLog',
    'DNS',
    'WinDefend',
    'MpsSvc'
)

$systemHealthy = $true

Write-Host ''
Write-Host '========================================='
Write-Host '       ENTERPRISE SERVICE HEALTH MONITOR'
Write-Host '========================================='
Write-Host ''

foreach ($service in $criticalServices) {
    try {
        $currentService = Get-Service -Name $service -ErrorAction Stop

        if ($currentService.Status -eq 'Running') {
            Write-Host (
                '{0,-40} {1}' -f
                $currentService.DisplayName,
                '[RUNNING]'
            )
        }
        else {
            Write-Host (
                '{0,-40} {1}' -f
                $currentService.DisplayName,
                '[STOPPED]'
            )

            $systemHealthy = $false
        }
    }
    catch {
        Write-Host (
            '{0,-40} {1}' -f
            $service,
            '[NOT FOUND]'
        )

        $systemHealthy = $false
    }
}

Write-Host ''
Write-Host '==========================================='

if ($systemHealthy) {
    Write-Host 'Overall System Status : HEALTHY'
    Write-Host 'Risk Level            : LOW'
}
else {
    Write-Host 'Overall System Status : ATTENTION REQUIRED'
    Write-Host 'Risk Level            : HIGH'
}

Write-Host '==========================================='
Write-Host 'Health Check Complete.'