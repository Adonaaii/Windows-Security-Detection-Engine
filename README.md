# Windows Security Detection Engine

A PowerShell-based security monitoring project that analyses Windows Security Event Logs and system activity to identify potentially suspicious behaviour.

This project was built as a hands-on security engineering lab to develop practical skills in Windows event analysis, PowerShell scripting, detection engineering, system monitoring, and basic event correlation.

## Features

### Privileged Logon Detection

Analyses Windows Security Event ID 4672 to identify accounts receiving special privileges.

The script:

- Extracts account and privilege information
- Identifies system and computer accounts
- Assigns a basic risk level
- Provides an investigation recommendation

### Failed Logon Detection

Analyses Windows Security Event ID 4625 to investigate failed authentication attempts.

The script extracts:

- Username and domain
- Source IP address
- Workstation
- Logon type
- Failure reason
- Status and sub-status codes

### Brute-Force Attack Correlation

Correlates failed logon events by username and time.

The detection rule generates a HIGH RISK alert when an account records five or more failed logons within a rolling 60-second window.

This demonstrates basic event correlation similar to detection logic used within SIEM platforms.

### Service Health Monitoring

Monitors critical Windows services including:

- Windows Event Log
- DNS Server
- Microsoft Defender Antivirus
- Windows Defender Firewall

The script reports the status of each service and provides an overall system health assessment.

### CPU Process Monitoring

Identifies the five processes with the highest accumulated CPU time above a configurable threshold and assigns basic severity levels.

Note: CPU time represents accumulated processor time in seconds and not current CPU utilisation percentage.

## Technologies and Concepts

- PowerShell
- Windows Server
- Windows Security Event Logs
- Event ID 4625
- Event ID 4672
- Get-WinEvent
- XML event parsing
- Hashtables
- PSCustomObject
- Event correlation
- Detection engineering
- Windows service monitoring
- Process monitoring
- Error handling

## Project Structure

```text
Windows-Security-Detection-Engine/
├── README.md
├── Scripts/
│   ├── AttackCorrelation.ps1
│   ├── FailedLogonDetector.ps1
│   ├── PrivilegedLogonDetector.ps1
│   ├── ServiceHealthMonitor.ps1
│   └── TopCPUProcess.ps1
├── Screenshots/
└── Archive/
```

## Running the Scripts

Open PowerShell with appropriate permissions and navigate to the `Scripts` directory.

For example:

```powershell
.\FailedLogonDetector.ps1
```

Access to the Windows Security log may require PowerShell to be run as Administrator.

## Screenshots

Screenshots demonstrating the scripts and their output are available in the `Screenshots` directory.

## Detection Limitations

This is a learning and portfolio project rather than a production security monitoring solution.

Current limitations include:

- Detection is performed against locally available Windows logs
- Risk levels use simple rule-based logic
- The brute-force rule uses a fixed threshold and time window
- There is no persistent alert storage
- There is currently no SIEM integration
- Detection rules may generate false positives and require analyst investigation

## Future Improvements

Potential improvements include:

- Correlating failed logons with subsequent successful logons
- Adding Event ID 4624 correlation
- Exporting alerts to JSON or CSV
- Adding Sysmon telemetry
- Integrating with a SIEM platform
- Adding automated tests
- Improving risk scoring based on source IP and account context

## Author

Samuel Asante