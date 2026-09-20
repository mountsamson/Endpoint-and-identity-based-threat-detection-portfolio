# Endpoint and Identity Based Threat Detection Portfolio

This repo holds my alert investigation reports from a SOC simulation lab. Each report walks through one alert from start to finish: what triggered it, what I found in the logs, and what I decided.

All the work was done in **Microsoft Defender for Endpoint** and **Microsoft Sentinel** against simulated attacks on a small Windows domain. The alerts cover things like credential theft with Mimikatz, Kerberoasting, malware hiding as a real Windows process, and password stealing tools run through PowerShell.

I write these to practise the day to day work of a SOC analyst: reading logs, following a process tree, mapping activity to MITRE ATT&CK, and explaining it clearly.

## Reports

| # | Alert | Severity | What it covers |
|---|-------|----------|----------------|
| 1 | Hands on keyboard attack from a compromised account | High | Mimikatz credential theft, LSASS access, lateral movement over RPC and WMI |
| 2 | Potential Kerberoasting activity | High | Domain recon with `nltest`, `net` and `setspn`, then service ticket theft (T1558.003) |
| 3 | Suspicious process executed PowerShell command | Medium | `wusvc.exe` masquerading as a Windows service, downloading and running LaZagne |

## What each report includes

- Case details: alert name, ID, severity and date investigated
- Alert summary: affected hosts and accounts, and why the rule fired
- Investigation findings: a timeline of what happened, backed by log evidence
- Evidence: process trees, file and process logs, IP addresses and command lines
- MITRE ATT&CK mapping where it applies

## Tools used

- Microsoft Defender for Endpoint (EDR)
- Microsoft Sentinel (SIEM)
- KQL for log queries
- MITRE ATT&CK for technique mapping

> **Note:** Everything here comes from a simulated lab environment. No real company data is included.
