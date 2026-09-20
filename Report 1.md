# 🔍 Alert Investigation Report

> **Platform:** SOC Simulation Project — WDLabs  
> **Environment:** Microsoft Defender for Endpoint / Microsoft Sentinel

---

## 📋 Case Details

| Field                 | Value                                                                                                |
| --------------------- | ---------------------------------------------------------------------------------------------------- |
| **Alert Name**        | Hands-on keyboard attack was launched from a compromised account (attack disruption)                 |
| **Alert ID / Link**   | 152 / https://security.microsoft.com/incident2/152/overview?tid=567ea528-4e82-40fa-914e-38c05fd69677 |
| **Analyst**           | Carl                                                                                                 |
| **Date Investigated** | 8:09PM AEST 13/09/2026                                                                               |
| **Severity**          | High                                                                                                 |

---

## 1. Alert Summary

- **Host / Account affected:** socsim-dc.socsim.local and socsim-srv01.socsim.local
- **Date & Time of alert:** 31 Aug 2026 14:51:53
- **What triggered the alert:** Mimikatz credential theft tool
- **Why it triggered (rule/logic):** A malicious file masquerading as svchost.exe

---

## 2. Investigation Findings

### What happened?
<!-- How was the activity executed or triggered? Walk through the technical detail. -->

- 1 Aug 2026, 14:51 — Attacker attempted lateral movement over RPC from socsim-dc.socsim.local using the dave.brown account; blocked on multiple devices.
- 31 Aug 2026, 19:26 — Password of an account was changed; this same account later performed malicious activity, suggesting the attacker already had enough access to manipulate credentials.
- 1 Sep 2026, 12:00 — Mimikatz credential theft tool detected on socsim-dc.socsim.local under dave.brown, marking the start of active credential harvesting from memory.
- 1 Sep 2026, 12:37 — Defender flagged potential human-operated malicious activity, confirming a live attacker rather than automated malware.
- 1 Sep 2026, 12:45 — Five alerts fired almost simultaneously on socsim-dc.socsim.local: compromised account conducting hands-on-keyboard attack, repeated human-operated malicious activity alerts, and malware detected during lateral movement.
- 1 Sep 2026, 13:02 — Sensitive credential memory read detected, indicating an active attempt to pull credentials from protected memory.
- 1 Sep 2026, 13:03 — Peak of the attack, with a dense burst of correlated alerts across socsim-dc.socsim.local and socsim-srv01.socsim.local:
    - Suspicious remote activity
    - Another human-operated malicious activity alert
    - Mimikatz detected again, this time on socsim-srv01 (lateral spread to a second server)
    - Suspicious PowerShell command execution
    - Malicious credential theft tool execution confirmed
    - System file masquerade (fake svchost.exe)
    - Suspicious WMI process creation (common remote-execution technique)
    - Another compromised-account hands-on-keyboard alert
    - Suspicious access to the LSASS service (blocked)
    - A second confirmed credential theft tool execution on socsim-dc.socsim.local
- 1 Sep 2026, 13:37 — Attacker attempted RPC-based lateral movement again across multiple devices, showing continued attempts to spread even after detection.

### Evidence
<!-- What artefacts, log entries, or indicators support your conclusion? -->

```
// Paste key log entries, process trees, or notable findings here
```
Process Tree
![[Pasted image 20260913204314.png|547]]

File Logs
![[Pasted image 20260913204354.png|540]]

Process Logs
![[Pasted image 20260913204423.png]]

IP address Logs
![[Pasted image 20260913204436.png]]

URL Logs
![[Pasted image 20260913204547.png]]

Activity Logs
![[Pasted image 20260913204746.png]]

Alerts
![[Pasted image 20260913204806.png]]
### Was the activity successful?
- [x] Yes
- [ ] No
- [ ] Unknown

### Verdict
- [x] **Malicious**
- [ ] **Non-malicious**
- [ ] **Suspicious — requires further investigation**

**Justification:**
<!-- Why did you reach this conclusion? Be specific. -->

This conclusion is based on direct evidence, not just the alert names. The Evidence tab showed the actual Mimikatz files (mimikatz.exe, mimilib.dll, mimispool.dll, mimidrv.sys) sitting on disk on socsim-srv01, confirming the tool was really present. The Process list showed lsass.exe itself flagged suspicious at the same timestamp — LSASS is the exact memory Mimikatz targets, proving credential theft was actually attempted. A URL entity pointed straight to the tool's real GitHub source (gentilkiwi/mimikatz), showing where it was downloaded from. The incident graph tied all of this to one account (dave.brown) moving from socsim-dc to socsim-srv01 via a disguised svchost.exe file and a PowerShell command. Finally, the Activities log showed Microsoft Defender's Attack Disruption engine independently took real response actions — quarantining the malicious file and containing the account — confirming this was treated as a genuine active compromise, not a false positive.


---

## 3. Investigation Steps

<!-- Walk through your process in order. What did you look at first? What led you to each pivot? -->

1.  The attack story - looking the tree process was easy to look at and understand
2.  The alerts told on how the attack story occurred  
3.  Opening up the investigate tab

### Queries Used

```kql
// Paste queries here
```
SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertSeverity == "High"
| project TimeGenerated, AlertName, AlertSeverity, Description, CompromisedEntity, Tactics
| sort by TimeGenerated desc

---

## 4. Categorisation

- [x] ✅ **True Positive** — malicious activity confirmed
- [ ] ⚠️ **Benign True Positive** — alert fired correctly, activity is legitimate
- [ ] ❌ **False Positive** — alert fired incorrectly, rule needs review

---

## 5. Recommended Actions

**Escalation:**
- [x] Urgent — phone call required
- [ ] Non-urgent — email sufficient
- [ ] No escalation required

**Containment / Next Steps:**
<!-- What should happen next? Free text — don't limit yourself to a checklist. -->

- Call the user to change passwords and perform windows defender virus scanning
- Call a meeting with seniors and other experts on this matter when stuck
- Recommand to always perform windwos update when possible
- Change all admin and service account passwords. The attacker stole credentials from the domain controller, so we have to assume they have them all.
- Reset the krbtgt password twice. This stops the attacker from creating fake login tickets that would let them back in.
- Lock the dave.brown account again. It was unlocked on 6 Sep and is currently active.
- Check that dave.brown's password was really changed. The attacker may have set it themselves on 31 Aug.
- Finish cleaning socsim-srv01. The Mimikatz alert still says only partly fixed.
- Delete the leftover bad files: mimikatz.exe, mimispool.dll, mimidrv.sys, m.zip, and the fake svchost.exe.
- Look closely at mimidrv.sys. It's a driver file, which means the attacker may have had deep access to the system.
- Rebuild both socsim-dc and socsim-srv01 instead of just cleaning them.
- Find out how the attacker got in. The alerts start on 31 Aug when the attack was already happening, so the break-in was earlier.
- Check dave.brown's login history from at least a week before 31 Aug. Look for strange IP addresses or failed logins.
- Check if 172.31.6.185 is a normal computer on the network or something unknown.
- Block internet downloads on servers. A domain controller was able to download Mimikatz straight from GitHub, which should not happen.
- Check what the administrator account was doing. It shows up in the incident graph, so it may have been used too.
- Assign this incident to someone and set a classification. 19 of the 23 alerts are still marked as New.

**Alert Tuning:**
- [ ] Tune recommended —
- [x] No tuning required

---

## 6. Lessons Learned

<!-- What would you do differently? Where did you go wrong or take a longer path than needed?
     This is the most valuable part of the write-up for your own growth and for anyone reading your portfolio. -->
     
 - looking at the process graph too long
 - could've done more deep diving on the logs
 - only looked the logs as a quick brief
 - looking at the investigation  page for too long 
 - used AI for too long to conclude investigation - more practice and reps on investigating incidents quick and use AI when the incident is too confusing to recognize 
 - Didnt use much KQL command much - manually browsing the alerts 

---

<details>
<summary>📚 About this template</summary>

This investigation template is from the **[SOC Simulation Project](https://www.skool.com/socsim/about)** by WDLabs / WebDefend Cyber Security — a hands-on training environment giving aspiring analysts access to Microsoft Defender for Endpoint and Microsoft Sentinel to investigate real alerts generated by emulated threat actor TTPs.

</details>