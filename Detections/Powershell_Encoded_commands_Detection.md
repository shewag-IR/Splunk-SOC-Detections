# Encoded PowerShell Commands Detection

## Overview

### Goal
Detect and respond to suspicious PowerShell activity including:
- **Encoded commands** (-Enc / -EncodedCommand parameters)
- **Process chaining** (PowerShell → cmd → PowerShell)
- **Discovery commands** (whoami, hostname, ipconfig)

Using Atomic Red Team for technique simulation and Splunk for telemetry analysis.

### Why This Matters
Encoded PowerShell and suspicious parent/child process chains are hallmark attacker evasion techniques. Early detection and response to these patterns significantly reduce dwell time and prevent lateral movement.

## Tools Used
- **Atomic Red Team** – Simulate attacker techniques in a controlled environment
- **Splunk** – Ingest, parse, and search Windows Event Logs and Sysmon telemetry
- **Sysmon** – Provide detailed process creation and parent/child tracking

## Environment and Test Setup

### Preparation
1. Deploy Atomic Red Team on an isolated test host
2. Execute PowerShell techniques that use encoded commands and process chaining
3. Enable Sysmon with process creation and parent process tracking enabled
4. Forward Windows Event Logs and Sysmon events to Splunk for ingestion

## Detection Queries

### Query 1: Find All PowerShell Process Creation Events
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
| table _time Computer User ParentImage Image CommandLine ProcessId ParentProcessId
```

**Purpose:** Baseline query to identify all PowerShell process spawning activity.

### Query 2: Detect Encoded PowerShell Commands
```spl
index=sysmon EventCode=1 (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*")
| table _time Computer User Image CommandLine ParentImage
```

**Purpose:** Flag PowerShell processes with encoded command parameters, a common obfuscation technique.

### Query 3: Detect PowerShell Spawning Discovery Tools
```spl
index=sysmon EventCode=1 (ParentImage="*\\powershell.exe" OR Image="*\\powershell.exe")
| search Image="*\\whoami.exe" OR Image="*\\hostname.exe" OR Image="*\\ipconfig.exe" OR Image="*\\cmd.exe"
| table _time Computer User ParentImage Image CommandLine
```

**Purpose:** Identify reconnaissance activity (whoami, hostname, ipconfig) spawned from PowerShell, indicative of post-compromise discovery.

### Query 4: Detect PowerShell ↔ cmd Process Chaining
```spl
index=sysmon EventCode=1
| transaction ParentProcessId startswith=(Image="*\\powershell.exe") endswith=(Image="*\\powershell.exe") maxspan=1m
| search eventcount>1
| table _time Computer User eventcount ParentImage Image CommandLine
```

**Purpose:** Identify the classic evasion pattern: PowerShell spawning cmd which then spawns PowerShell (used to bypass execution policies and logging).

## Saved Search Template

Use this JSON as a template for a Splunk saved search. Customize `cron_schedule`, `alert_actions`, and whitelist exclusions for your environment.

```json
{
  "name": "Detect_Encoded_PowerShell_and_Chaining",
  "search": "index=sysmon EventCode=1 (CommandLine=\"*-enc*\" OR CommandLine=\"*-EncodedCommand*\" OR (ParentImage=\"*\\powershell.exe\" AND (Image=\"*\\cmd.exe\" OR Image=\"*\\powershell.exe\"))) | stats count by Computer, User, ParentImage, Image, CommandLine, _time | where count > 0",
  "cron_schedule": "*/5 * * * *",
  "alert_type": "number of events",
  "alert_condition": "count > 0",
  "severity": "high",
  "actions": ["notable", "email"],
  "throttle": "5m",
  "description": "Alert on encoded PowerShell commands and suspicious PowerShell→cmd→PowerShell chains. Whitelist trusted automation and scripts to reduce false positives."
}
```

## Findings and Tuning

### Observed Indicators
- powershell.exe spawned **whoami.exe** and **hostname.exe**, indicating environment discovery
- Command lines containing **-enc** or **-EncodedCommand** parameters present
- **Process chain**: powershell.exe → cmd.exe → powershell.exe observed, consistent with known evasion patterns
- Encoded payloads detected at unusual hours or from non-standard user accounts

### Tuning and Noise Reduction Recommendations
1. **Whitelist trusted scripts and automation** by matching CommandLine patterns or Image hashes
2. **Exclude known scheduled tasks** – administrator-initiated maintenance and backup operations
3. **Prioritize high-fidelity alerts:**
   - Encoded PowerShell from non-administrator accounts
   - Process chaining from unexpected parent processes
   - Discovery commands from newly created or suspicious user sessions
4. **Enrich detections** by correlating with:
   - Network connections (e.g., reverse shells)
   - File writes to system directories
   - AMSI failures or Script Block Logging errors
5. **Tune by time and context** – cluster alerts by Computer and User to spot compromises

## Hardening and Logging Improvements

To improve detection coverage and reduce false positives:

- **Enable PowerShell Script Block Logging** (Event ID 4104) and Module Logging (Event ID 4103)
- **Deploy Sysmon** with process creation and parent process tracking enabled
- **Monitor AMSI** (Antimalware Scan Interface) and log failures
- **Enforce Constrained Language Mode** on high-risk endpoints
- **Enrich process telemetry** with:
  - Authenticode signing status
  - Process hashes (MD5, SHA-256)
  - User role and privilege level
  - Command-line parent execution context

## References
- [Atomic Red Team: PowerShell Obfuscation](https://github.com/redcanaryco/atomic-red-team/)
- [Sysmon Event ID 1: Process Creation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)