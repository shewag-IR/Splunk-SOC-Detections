Suspicious PowerShell Detection README

Overview
Goal
Practice detecting suspicious PowerShell activity such as encoded commands, process chaining (PowerShell → cmd → PowerShell), and discovery commands (whoami, hostname) using Atomic Red Team for simulation and Splunk for telemetry analysis.
Tools used
- Atomic Red Team to simulate attacker techniques.
- Splunk to ingest and search Windows Event Logs and Sysmon telemetry.

Environment and test setup
Preparation
- Deployed Atomic Red Team on a dedicated test host and executed PowerShell techniques that use encoded commands and process chaining.
- Enabled Sysmon with process creation and parent process tracking.
- Forwarded Windows Event Logs and Sysmon events to Splunk.
Why this matters
Encoded PowerShell (-Enc / -EncodedCommand) and unusual parent/child process chains are common attacker evasion techniques and high‑value detection targets.

Splunk queries
Find PowerShell process creation events from Sysmon
index=sysmon EventCode=1 Image="*\\powershell.exe"
| table _time Computer User ParentImage Image CommandLine ProcessId ParentProcessId


Find command lines containing encoded PowerShell
index=sysmon EventCode=1 (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*")
| table _time Computer User Image CommandLine ParentImage


Find PowerShell spawning discovery tools
index=sysmon EventCode=1 (ParentImage="*\\powershell.exe" OR Image="*\\powershell.exe")
| search Image="*\\whoami.exe" OR Image="*\\hostname.exe" OR Image="*\\cmd.exe"
| table _time Computer User ParentImage Image CommandLine


Detect PowerShell cmd PowerShell chaining using transaction
index=sysmon EventCode=1
| transaction ParentProcessId startswith=(Image="*\\powershell.exe") endswith=(Image="*\\powershell.exe") maxspan=1m
| search eventcount>1
| table _time Computer User eventcount ParentImage Image CommandLine



Saved search template
Use this JSON as a template for a Splunk saved search. Adjust cron_schedule, alert_actions, and whitelist to match your environment.
{
  "name": "Detect_Encoded_PowerShell_and_Chaining",
  "search": "index=sysmon EventCode=1 (CommandLine=\"*-enc*\" OR CommandLine=\"*-EncodedCommand*\" OR (ParentImage=\"*\\\\powershell.exe\" AND (Image=\"*\\\\cmd.exe\" OR Image=\"*\\\\powershell.exe\"))) | stats count by Computer User ParentImage Image CommandLine _time | where count > 0",
  "cron_schedule": "*/5 * * * *",
  "alert_type": "number of events",
  "alert_condition": "count > 0",
  "severity": "high",
  "actions": ["notable", "email"],
  "throttle": "5m",
  "description": "Alert on encoded PowerShell commands and suspicious PowerShell->cmd->PowerShell chains. Tune whitelist to reduce noise."
}



Findings and tuning
Observed indicators
- powershell.exe spawned whoami.exe and hostname.exe indicating environment discovery.
- Command lines containing -enc / -EncodedCommand were present.
- Process chain powershell.exe → cmd.exe → powershell.exe observed, consistent with evasion patterns.
Tuning recommendations
- Whitelist known automation and signed scripts by matching CommandLine or Image.
- Exclude trusted admin hosts and scheduled maintenance windows.
- Prioritize alerts where non‑admin users or unusual parent processes are involved.
- Correlate with network connections, file writes, and AMSI failures to reduce false positives.

Hardening and logging improvements
- Enable PowerShell Script Block Logging and Module Logging.
- Deploy Sysmon with process creation and parent process tracking enabled.
- Monitor AMSI and log AMSI failures.
- Consider Constrained Language Mode for high‑risk endpoints.
- Enrich telemetry with endpoint context such as process hashes, signing status, and user role.


