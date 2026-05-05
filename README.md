🔍 Threat Hunt — Unauthorized TOR Browser Usage
Project: Project Basilio — SOC Lab Architecture
Date: April 25–27, 2026
Platform: Microsoft Defender for Endpoint | Microsoft Sentinel | Advanced Hunting (KQL)
Endpoint: virtualtest11 (IP: 10.0.0.141)
User Account: bthrasher80
MITRE ATT&CK: T1090.003 – Proxy: Multi-hop Proxy | T1486 – Data Encrypted for Impact

🎯 Objective
Investigate suspected unauthorized TOR browser usage on endpoint virtualtest11 following management reports of unusual encrypted traffic patterns and employee discussions about bypassing network security controls. Determine whether TOR was installed and used, reconstruct the full activity timeline, identify associated malicious activity, and document findings with IOCs for escalation.

🧠 Hunt Hypotheses
Five hypotheses were formed before querying any data:

H1: A user on virtualtest11 downloaded and silently installed the TOR browser portable package.
H2: The TOR process (tor.exe) was executed under a standard user account, not a system account.
H3: The device established outbound connections to known TOR relay nodes on port 9001.
H4: TOR established a local SOCKS proxy on 127.0.0.1, routing traffic anonymously.
H5: Secondary malicious activity (data staging or ransomware execution) followed TOR usage.

All five hypotheses were confirmed by telemetry.

🛠️ Tools & Environment
ComponentDetailsDetection PlatformMicrosoft Defender for EndpointQuery LanguageKQL (Kusto Query Language)WorkspaceLAW-Cyber-Range / Microsoft SentinelTables QueriedDeviceFileEvents, DeviceProcessEvents, DeviceNetworkEventsEndpointvirtualtest11 — Windows, Proxmox VMActivity WindowApril 25, 2026 – April 27, 2026

🔎 KQL Queries Used
Query 1 — TOR File Activity (DeviceFileEvents)
Searched for file events associated with user bthrasher80 where the filename contained 'tor'. Revealed TOR installer activity and creation of a file named 'Tor-Shopping-List'.
kqlDeviceFileEvents
| where DeviceName == "virtualtest11"
| where InitiatingProcessAccountName == "bthrasher80"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
  Account = InitiatingProcessAccountName
Query 2 — Silent Installation Detection (DeviceProcessEvents)
Searched for process command lines referencing the TOR portable installer to detect silent installation.
kqlDeviceProcessEvents
| where DeviceName == "virtualtest11"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable"
| project Timestamp, DeviceName, AccountName, ActionType, FileName,
  FolderPath, SHA256, ProcessCommandLine
Query 3 — TOR Process Execution (DeviceProcessEvents)
Confirmed execution of tor.exe and tor-browser.exe under the user account.
kqlDeviceProcessEvents
| where DeviceName == "virtualtest11"
| where FileName has_any ("tor.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName,
  FolderPath, SHA256, ProcessCommandLine
Query 4 — TOR Network Connections (DeviceNetworkEvents — Time-Scoped)
Scoped to the activity window to eliminate baseline noise. Filtered for connections initiated by tor.exe on known TOR relay ports.
kqlDeviceNetworkEvents
| where DeviceName == "virtualtest11"
| where Timestamp between (datetime(2026-04-25) .. datetime(2026-04-28))
| where InitiatingProcessFileName == "tor.exe"
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, ActionType
| order by Timestamp asc
Query 5 — pwncrypt Ransomware File Activity (DeviceFileEvents — Time-Scoped)
Searched for files containing 'pwncrypt' in the activity window to identify ransomware staging and file encryption events.
kqlDeviceFileEvents
| where DeviceName == "virtualtest11"
| where Timestamp between (datetime(2026-04-25) .. datetime(2026-04-28))
| where FileName contains "pwncrypt"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName

📅 Chronological Event Timeline
TimestampEventTableKey FindingApr 25, 2026 07:18:20 AMtor.exe first executedDeviceProcessEventsUser bthrasher80 launched tor.exe from C:\Users\bthrasher80\DesktopApr 25, 2026 07:18:21 AMTOR SOCKS proxy establishedDeviceNetworkEventsListeningConnectionCreated on 127.0.0.1:51613 and 127.0.0.1:51615Apr 25, 2026 07:20:26 AMFirst outbound TOR relay connectionDeviceNetworkEventsConnectionSuccess to 37.221.195.103:9001Apr 25, 2026 07:20:27 AMTOR hidden service URI resolvedDeviceNetworkEventsConnectionSuccess via https://www.ykawzx7s2gfsvh7iw3snm.com — active TOR routing confirmedApr 25, 2026 07:20:29 AMAdditional TOR relay connectionsDeviceNetworkEventsConnectionSuccess to 141.95.86.17:9001 and 212.227.127.105:9001Apr 25, 2026 08:12:52 AMpwncrypt.ps1 dropped to diskDeviceFileEventsFileCreated: pwncrypt.ps1 at C:\ProgramData\pwncrypt\ — initiated by powershell.exeApr 25, 2026 08:12:56 AMFile encryption begins — Round 1DeviceFileEventsFileCreated + FileRenamed across CompanyFinancials, ProjectList, EmployeeRecordsApr 25, 2026 12:12:05 PMpwncrypt.ps1 re-executed — Round 2DeviceFileEventsSecond encryption cycle beginsApr 25, 2026 04:12:58 PMpwncrypt.ps1 re-executed — Round 3DeviceFileEventsThird encryption cycleApr 25–26, 2026 (Multiple)Sustained TOR relay activityDeviceNetworkEventsContinued ConnectionSuccess to 141.95.86.17:9001 and 212.227.127.105:9001Apr 27, 2026 11:38:10 AMtor.exe re-executed — Session 2DeviceProcessEventsSOCKS proxy on 127.0.0.1:58291. Relay connections resumeApr 27, 2026 11:40:10 AMtor.exe re-executed — Session 3DeviceProcessEventsSOCKS proxy on 127.0.0.1:58391 and 58393Apr 27, 2026 12:28:46 PMTor-Shopping-List.lnk createdDeviceFileEventsFileCreated in Recent Items — accessed via Guacamole RDP from 10.0.8.9. Confirms premeditated intentApr 27, 2026 12:35:50 PMtor.exe re-executed — Session 4DeviceProcessEventsFourth and final confirmed TOR execution. Same SHA256 as all prior sessions

🚨 Indicators of Compromise (IOCs)
TypeValueContextProcesstor.exeExecuted 4 times by bthrasher80. Path: C:\Users\bthrasher80\Desktop\SHA256a028d058c4d49cf0df10...Consistent across all 4 tor.exe executions — single binary used throughoutIP Address37.221.195.103TOR relay node. ConnectionSuccess on port 9001. First contact Apr 25 at 7:20 AMIP Address141.95.86.17TOR relay node. Repeated ConnectionSuccess on port 9001 across Apr 25–27IP Address212.227.127.105TOR relay node. Repeated ConnectionSuccess on port 9001 across Apr 25–27Filepwncrypt.ps1Ransomware script dropped to C:\ProgramData\pwncrypt\ by powershell.exe. Executed 3 timesFileTor-Shopping-List.lnkWindows shortcut in Recent Items. Created Apr 27 at 12:28 PM during RDP session from 10.0.8.9. Confirms deliberate intent

📋 Summary of Findings
Between April 25 and April 27, 2026, user bthrasher80 on endpoint virtualtest11 deliberately installed, configured, and repeatedly used the TOR browser to anonymize network activity. The investigation uncovered a multi-day escalation pattern from TOR browser installation to ransomware execution.
On April 25 at 7:18 AM, tor.exe was executed from the Desktop. Within two minutes the TOR client established a local SOCKS proxy on 127.0.0.1 and began routing traffic through relay nodes on port 9001. Multiple .onion-style URIs were resolved, confirming active browsing through the TOR anonymization network.
Approximately one hour after the first TOR session, pwncrypt.ps1 was dropped to C:\ProgramData\pwncrypt\ by powershell.exe and immediately began encrypting files. Three categories of company data were targeted: CompanyFinancials, ProjectList, and EmployeeRecords. The encryption pattern consisted of FileCreated events on the Desktop followed by FileRenamed events moving originals to C:\Windows\Temp. This cycle ran three separate times on April 25 at 8:12 AM, 12:12 PM, and 4:12 PM.
TOR activity resumed on April 27 with three additional tor.exe executions. At 12:28 PM on April 27, Tor-Shopping-List.lnk was created in the Recent Items folder during a remote RDP session from 10.0.8.9 via Guacamole RDP — confirming deliberate premeditated intent.
In total, tor.exe was executed four confirmed times across two days. The same SHA256 hash was present in all four executions.

🛡️ Response Actions Taken

Endpoint virtualtest11 isolated from the network to prevent further exfiltration or C2 activity
User's direct manager notified of confirmed TOR usage and associated ransomware activity
All findings, query results, and IOCs documented and preserved for investigation and potential HR/legal action
Encrypted files (CompanyFinancials, ProjectList, EmployeeRecords variants) flagged for recovery assessment


📷 Evidence
Screenshots in the /screenshots directory demonstrate:

KQL queries for file, process, and network event hunting
TOR network connections to relay nodes on port 9001 with .onion URI resolution
Timeline visualization of connection activity across Apr 25–26
pwncrypt ransomware FileCreated and FileRenamed events across three encryption cycles
Tor-Shopping-List.lnk artifact with full record inspection showing Guacamole RDP session
DeviceNetworkEvents filtered to tor.exe initiating process
Sentinel Advanced Hunting workspace — LAW-Cyber-Range


🧠 Security & SOC Relevance
This investigation demonstrates the end-to-end threat hunt workflow used in enterprise SOC environments:

Hypothesis-driven hunting — five hypotheses formed before touching data, all confirmed
Multi-table correlation — process, file, and network events correlated across DeviceProcessEvents, DeviceFileEvents, and DeviceNetworkEvents
Time-scoping technique — query refinement to eliminate baseline noise and isolate the activity window
IOC documentation — SHA256 hashes, IP addresses, and file artifacts documented for threat intel and detection rule creation
ATT&CK mapping — T1090.003 (Multi-hop Proxy) and T1486 (Data Encrypted for Impact) confirmed
Artifact significance — Tor-Shopping-List.lnk as a premeditation indicator demonstrates Windows forensic artifact awareness


💡 Lessons Learned

Time-scoping queries is essential when working against noisy datasets — unscoped network queries returned irrelevant results until the activity window was bounded
The Tor-Shopping-List.lnk artifact in Recent Items is a Windows forensic artifact demonstrating that file access leaves traces even when the file itself is later deleted
Ransomware activity followed TOR usage within one hour — the connection between anonymization and payload delivery is a pattern worth hunting proactively
Consistent SHA256 across four tor.exe executions confirms persistence of the same binary and rules out re-download scenarios


✅ Status
Artifact: COMPLETE ✅ — Threat hunt conducted, full timeline reconstructed, IOCs documented, response actions taken.

"I conducted a threat hunt for unauthorized TOR browser usage using Microsoft Defender for Endpoint Advanced Hunting with KQL. I queried DeviceProcessEvents, DeviceNetworkEvents, and DeviceFileEvents to reconstruct the full attack timeline — from TOR installation through active relay connections on port 9001 to pwncrypt ransomware execution — across a three-day activity window on virtualtest11, documented in the Project Basilio GitHub repository."
