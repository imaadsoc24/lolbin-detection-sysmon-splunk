# LOLBIN Detection — Sysmon + Splunk

This lab demonstrates detection of Living Off The Land Binary (LOLBIN) abuse using Sysmon telemetry and Splunk SIEM.

The objective was to understand how attackers use trusted Windows binaries to evade detection and how SOC analysts identify them through log analysis.

## Attack Scenario

A suspicious execution of `rundll32.exe` was simulated from PowerShell to mimic attacker behaviour.

LOLBINs are commonly abused because they are trusted by the operating system and often bypass traditional antivirus detection.

# Detection Logic

Telemetry Source: Sysmon Event ID 1 (Process Creation)

Suspicious Indicators:
- rundll32.exe execution
- Parent process: PowerShell
- High integrity level
- Unusual command line arguments

## Splunk Detection Query

index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="rundll32.exe" | table _time Image CommandLine ParentImage User Computer IntegrityLevel

## MITRE ATT&CK Mapping

Technique: T1218.011 — Signed Binary Proxy Execution (Rundll32)

## Skills Practiced

- SIEM Investigation
- Endpoint Detection
- Threat Hunting
- Log Analysis
- SOC Workflow Understanding


## Lab Environment
---

## Screenshots

### Splunk Detection Result
![Splunk Detection](screenshots/splunk-detection.png)

### Event Details
![Event Details](screenshots/event-details.png)

### Timeline View
![Timeline](screenshots/timeline.png)

Attacker Machine: Windows  
Monitoring: Sysmon  
SIEM: Splunk Enterprise

This project focuses on detection engineering — identifying malicious behavior rather than generating it.
