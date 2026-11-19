# Windows Security Detection Engine

A PowerShell lab for Windows event analysis and detection engineering. The scripts extract authentication evidence from the Windows Security log and help decide which events to investigate.

| Detection | Evidence |
| --- | --- |
| [Failed logons](scripts/FailedLogonDetector.ps1) | Event 4625 with account, source IP, logon type and failure details |
| [Privileged logons](scripts/PrivilegedLogonDetector.ps1) | Event 4672 with account and privilege details |
| [Failed-logon correlation](scripts/AttackCorrelation.ps1) | Five or more failures for one username within a rolling 60-second window |
| [Service health](scripts/ServiceHealthMonitor.ps1) | Status of selected Windows, DNS and Defender services |
| [Process monitoring](scripts/TopCPUProcess.ps1) | Processes ranked by accumulated CPU time |

## Run the lab

Open PowerShell on a Windows host that records Security events. Use an elevated shell if your account needs it to read the Security log. From the repository root:

```powershell
.\scripts\FailedLogonDetector.ps1
.\scripts\AttackCorrelation.ps1
```

[See an example correlation alert](screenshots/AttackCorrelation.png) or [browse the example outputs](screenshots).

The correlation script examines the latest 100 failed-logon events. An alert is a triage lead. Stale credentials or a misconfigured service can also produce repeated failures.
