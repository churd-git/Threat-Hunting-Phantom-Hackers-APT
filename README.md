![Dont-let-AI-phantom-hackers-drain-your-bank-account](https://github.com/user-attachments/assets/63e28bd3-026f-44f3-a0c6-d1fee3c3d270)

# Threat-Hunting-Phantom-Hackers-APT (T1566, T1059, T1056.001, T1567) 

## Example Scenario:

At Acme Corp, the eccentric yet brilliant IT admin, Bubba Rockerfeatherman III, isn’t just patching servers and resetting passwords — he’s the secret guardian of trillions in digital assets. Hidden deep within encrypted vaults lie private keys, sensitive data, and intellectual gold... all protected by his privileged account. But the shadows have stirred. A covert APT group known only as The Phantom Hackers 👤 has set their sights on Bubba. Masters of deception, they weave social engineering, fileless malware, and stealthy persistence into a multi-stage campaign designed to steal it all — without ever being seen. The breach has already begun. Using phishing, credential theft, and evasive tactics, the attackers have infiltrated Acme’s network. Bubba doesn’t even know he's compromised. Hunt through Microsoft Defender for Endpoint (MDE) telemetry, analyze signals, query using KQL, and follow the breadcrumbs before the keys to Bubba’s empire vanish forever.


Important Context:
- Look for the name of any suspicious file or binary that resembles an antivirus but is responsible for the malicious activity.

Known Information:
- DeviceName: anthony-001

---

## High-Level Command and Scripting Interpreter: PowerShell related IoC Discovery Plan:

1. Check DeviceFileEvents for any new suspicious file activity on the device "anthony-001".
2. Check DeviceProcessEvents for activity involving the newly downloaded malicious program.
3. Search DeviceRegistryEvents to check the registry to confirm persistence activity.
4. Check DeviceEvents for suspicious activity as well. 

---

## Steps Taken

1. Searched the DeviceFileEvents for suspicious activity from "anthony-001". The primary focus was to look for activity involving new executable files that are out of the ordinary. Discovered on May 6th at "2025-05-07T02:00:36.794406Z" a user under the account name "4nth0ny!" downloaded a file named "BitSentinelCore.exe". This is a malicious file that was trying to disguise itself as sentinel anti-virus software. The program was downloaded via command line using the command ""csc.exe" /noconfig /fullpaths @"C:\Users\4nth0ny!\AppData\Local\Temp\c5gy0jzg\c5gy0jzg.cmdline". The attackers used tcsc.exe to download the program in an attempt to disguise their actions using living off the land techniques. All this was done via remote IP "192.168.0.110" which is likely the APT's IP.
     
```kql
DeviceFileEvents 
| where DeviceName has "anthony-001"
| where InitiatingProcessAccountName contains "4nth0ny!"
| where FileName contains ".dll" or FileName contains ".exe"
```
<img width="1379" alt="Screenshot 2025-05-19 at 9 22 20 PM" src="https://github.com/user-attachments/assets/6ff376e9-1485-4ea9-a4b8-86494b7705a0" />


2. Investigated DeviceProcessEvents for any activity involving the newly downloaded malicious program. Based on the evidence in the logs on May 6th shortly after the file was downloaded at "2025-05-07T02:02:14.6264638Z" it was executed which triggered a string of events. Ultimately the file executed and it launched the command line and executed the following code ""cmd.exe" /c schtasks /Create /SC DAILY /TN "UpdateHealthTelemetry" /TR "C:\ProgramData\BitSentinelCore.exe" /ST 14:00". This command then launched this secondary command "schtasks  /Create /SC DAILY /TN "UpdateHealthTelemetry" /TR "C:\ProgramData\BitSentinelCore.exe" /ST 14:00". The end result was the creation of a scheduled task named "UpdateHealthTelemetry" which provides APT with persistence in the system. 

```kql
DeviceProcessEvents 
| where DeviceName contains "anthony-001"
| where ProcessCommandLine contains "BitSentinel"
```
<img width="1369" alt="Screenshot 2025-05-19 at 9 34 40 PM" src="https://github.com/user-attachments/assets/9b39fe91-eb35-481d-b74b-df8bf3826733" />


3. After identifying that the APT executed their program to establish persistence, in order to confirm the DeviceRegistryEvents was investigated to look dor any registry changes. At "2025-05-07T02:02:14.9669902Z" there was a new RefistryValueSet associated with the BitSentinelCore.exe. The registry value name was called "BitSecSvc". This confirmed that persistence was established as planned by the attacker.

```kql
DeviceRegistryEvents 
| where DeviceName == "anthony-001"
| where RegistryValueData contains "sentinel"
```
<img width="1386" alt="Screenshot 2025-05-19 at 9 41 44 PM" src="https://github.com/user-attachments/assets/7e79c1f3-42bc-47b2-9726-5bb9cf4fa8b3" />

4. Lastly the DeviceEvents log was inspected for any other suspicious activity on the compromised machine. After searching for any activity that occured after the compromised machine has initiated the their malicious software and achieved persistence, it was discovered that they had also installed keylogging software to steal information from their target. At "2025-05-07T02:06:51.3594039Z" on May 6th a ShellLinkCreateFileEvent was created called "systemreport.lnk". This malicious file was downloaded from the internet and runs a keylogger when clicked. The threat actors took it a step further as they set it up to be initiated via userinit.exe. This means that the process would be initiated on start-up ensuring the computer is compromised at all times.

```kql
DeviceEvents
| where DeviceName == "anthony-001"
| where InitiatingProcessAccountName == "4nth0ny!"
| where ActionType == "ShellLinkCreateFileEvent"
| where Timestamp >= datetime(2025-05-07T02:02:14.6264638Z)
```
<img width="1379" alt="Screenshot 2025-05-19 at 9 56 30 PM" src="https://github.com/user-attachments/assets/c39b30b0-7a4c-4373-9feb-0e7abc215918" />

---

## Chronological Events

### 1. Initial Malicious File Download and Execution

- **Timestamp:** 2025-05-07T02:00:36.794406Z
- **Device:** anthony-001
- **User:** 4nth0ny!
- **Activity:**
    - User downloaded a suspicious file named `BitSentinelCore.exe` (masquerading as Sentinel antivirus software).
    - Downloaded via command line:
      ```
      csc.exe /noconfig /fullpaths @"C:\Users\4nth0ny!\AppData\Local\Temp\c5gy0jzg\c5gy0jzg.cmdline"
      ```
    - Source IP: 192.168.0.110 (suspected APT actor).
    - Technique: Living off the Land (LotL) using legitimate system tools.

---

### 2. Malicious Program Execution & Persistence

- **Timestamp:** 2025-05-07T02:02:14.6264638Z
- **Device:** anthony-001
- **User:** 4nth0ny!
- **Activity:**
    - `BitSentinelCore.exe` executed, triggering the creation of a daily scheduled task for persistence:
      ```
      schtasks /Create /SC DAILY /TN "UpdateHealthTelemetry" /TR "C:\ProgramData\BitSentinelCore.exe" /ST 14:00
      ```
    - Ensured the malware would run daily.

---

### 3. Registry Modification for Persistence

- **Timestamp:** 2025-05-07T02:02:14.9669902Z
- **Device:** anthony-001
- **User:** 4nth0ny!
- **Activity:**
    - New registry value, `BitSecSvc`, set to maintain persistence tied to the malicious executable.

---

### 4. Keylogger Deployment via Malicious Shell Link

- **Timestamp:** 2025-05-07T02:06:51.3594039Z
- **Device:** anthony-001
- **User:** 4nth0ny!
- **Activity:**
    - Malicious shortcut (`systemreport.lnk`) was created.
    - Designed to launch a keylogger (on click or at logon).
    - Set up via `userinit.exe` for execution at system start-up
      
---

## Summary

In this project, I conducted a threat hunt in response to a simulated advanced persistent threat (APT) campaign targeting Acme Corp’s privileged IT administrator, Bubba Rockerfeatherman III. The scenario revolved around "The Phantom Hackers," a covert group aiming to gain access to sensitive digital assets by compromising Bubba’s privileged account through a series of sophisticated, stealthy attacks.

The attack unfolded in multiple phases: starting with social engineering and phishing to gain initial access, the adversaries leveraged fileless malware, living-off-the-land binaries, and deceptive binaries disguised as legitimate security tools. Their end goal was to establish persistence, evade detection, and ultimately exfiltrate sensitive information, including credentials and private keys.

Using Microsoft Defender for Endpoint (MDE) telemetry and KQL queries, I investigated activity on the compromised endpoint (anthony-001). Key findings included the download and execution of a malicious binary (BitSentinelCore.exe) masquerading as anti-virus software, the creation of a persistent scheduled task and registry changes, and the deployment of a keylogger to capture credentials. Each suspicious action was correlated with specific MITRE ATT&CK techniques, providing a clear mapping of the attack chain.

---

## Response Taken
The device involved in this incident was quarantined in order to do prevent further damage and perform a deep analysis. Following the analysis the compromised device was be wiped and restored to a time prior it's compromised state. The evidence acquired during this investigation was handed over to the appropriate stakeholders for actions. Afterwards a more thorough investigation was launched in order to identify lessons learned to avoid this incident in future scenarios. The resulting recommendations made based on the incident was: 
- Security awareness training for the organization
- MFA on devices
- Principle of least privilege policy implementation
- Separation of duties implementation
- More strict allow and deny configurations on firewalls and endpoints.     

---

## Created By:
- **Author Name**: Carlton Hurd
- **Author Contact**: https://www.linkedin.com/in/carlton-hurd-6069a5120/
- **Date**: May 19th, 2025

## Validated By:
- **Reviewer Name**: Carlton Hurd
- **Reviewer Contact**: 
- **Validation Date**: March 19th, 2025 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 19th, 2025`  | `Carlton Hurd`   
