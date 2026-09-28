# Endpoint and Identity Based Threat Detection Portfolio

This repo holds my alert investigation reports from a SOC simulation lab. Each report walks through one alert from start to finish: what triggered it, what I found in the logs, and what I decided.

All the work was done in Microsoft Defender for Endpoint and Microsoft Sentinel against simulated attacks on a small Windows domain. The alerts cover things like credential theft with Mimikatz, Kerberoasting, malware hiding as a real Windows process, password stealing tools run through PowerShell, WDigest plaintext credential caching, and registry hive dumping to steal local password hashes.

I write these to practise the day to day work of a SOC analyst: reading logs, following a process tree, decoding obfuscated commands, mapping activity to MITRE ATT&CK, and explaining it clearly.

## Reports

| # | Alert | Severity | What it covers |
|---|-------|----------|----------------|
| 1 | Hands on keyboard attack from a compromised account | High | Mimikatz credential theft, LSASS access, lateral movement over RPC and WMI |
| 2 | Potential Kerberoasting activity | High | Domain recon with nltest, net and setspn, then service ticket theft (T1558.003) |
| 3 | Suspicious process executed PowerShell command | Medium | wusvc.exe masquerading as a Windows service, downloading and running LaZagne |
| 4 | Suspicious DPAPI Activity | High | Caldera agent installed as a service with NSSM, PowerShell downloading Mimikatz (blocked by Defender), then a fallback search for KeePass and Password Safe vault files |
| 5 | WDigest configuration change | Low | Ansible-delivered, double base64-encoded PowerShell setting `UseLogonCredential` to 1 so Windows caches plaintext passwords in LSASS memory |
| 6 | Sensitive information theft activity via Security Account Manager | High | Caldera agent recon, lateral movement to a second server with `net use` and WMI, LaZagne, then `reg save` of the SAM, SECURITY and SYSTEM hives (T1003.002) |

## What each report includes

- Case details: alert name, ID, severity and date investigated
- Alert summary: affected hosts and accounts, and why the rule fired
- Investigation findings: a timeline of what happened, backed by log evidence
- Evidence: process trees, file and process logs, IP addresses, decoded command lines and KQL queries
- MITRE ATT&CK mapping where it applies

## Themes across the reports

Reports 3 to 6 are linked. The same masquerading agent, `wusvc.exe` (a MITRE Caldera SandCat beacon that calls back to a C2 server), shows up in each of them, and the later reports follow what the operator did with it: install persistence, run recon, steal credentials, and move to another host. Reading them in order gives a view of one simulated intrusion from several different alert angles.

## Tools used

- Microsoft Defender for Endpoint (EDR)
- Microsoft Sentinel (SIEM)
- KQL for log queries, including Advanced Hunting on `DeviceProcessEvents` and `DeviceRegistryEvents`
- MITRE ATT&CK for technique mapping

> **Note:** Everything here comes from a simulated lab environment. No real company data is included.
