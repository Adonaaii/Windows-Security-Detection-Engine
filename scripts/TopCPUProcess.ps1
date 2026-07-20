<#
.SYNOPSIS
    Reports processes with high accumulated CPU time.

.DESCRIPTION
    Retrieves running processes that have accumulated more than a
    configurable number of seconds of processor time. The five processes
    with the highest CPU time are displayed and assigned a basic severity
    level.

    Note: The CPU property represents accumulated processor time in
    seconds, not current CPU utilisation percentage.

.NOTES
    Author: Samuel Asante
#>

$cpuTimeThreshold = 10
$maximumProcesses = 5

Write-Host ''
Write-Host '========================================='
Write-Host '           TOP CPU PROCESS REPORT'
Write-Host '========================================='
Write-Host ''

try {
    $topProcesses = Get-Process -ErrorAction Stop |
        Where-Object { $_.CPU -gt $cpuTimeThreshold } |
        Sort-Object CPU -Descending |
        Select-Object -First $maximumProcesses ProcessName, Id, CPU

    if ($topProcesses) {
        $topProcesses | Format-Table -AutoSize

        foreach ($process in $topProcesses) {
            if ($process.CPU -gt 100) {
                $riskLevel = 'HIGH'
            }
            elseif ($process.CPU -gt 50) {
                $riskLevel = 'MEDIUM'
            }
            else {
                $riskLevel = 'LOW'
            }

            Write-Host (
                "[$riskLevel] $($process.ProcessName) has accumulated " +
                "$([math]::Round($process.CPU, 2)) seconds of CPU time."
            )
        }

        Write-Host ''
        Write-Host (
            "WARNING: One or more processes have accumulated more than " +
            "$cpuTimeThreshold seconds of CPU time."
        )
    }
    else {
        Write-Host (
            "No processes exceeded $cpuTimeThreshold seconds of CPU time."
        )
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)"
}

Write-Host ''
Write-Host 'Report Complete.'