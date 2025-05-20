# Threat-Hunting-Phantom-Hackers-APT (T1566, T1059, T1056.001, T1567) 

## Example Scenario:

At Acme Corp, the eccentric yet brilliant IT admin, Bubba Rockerfeatherman III, isn’t just patching servers and resetting passwords — he’s the secret guardian of trillions in digital assets. Hidden deep within encrypted vaults lie private keys, sensitive data, and intellectual gold... all protected by his privileged account. But the shadows have stirred. A covert APT group known only as The Phantom Hackers 👤 has set their sights on Bubba. Masters of deception, they weave social engineering, fileless malware, and stealthy persistence into a multi-stage campaign designed to steal it all — without ever being seen. The breach has already begun. Using phishing, credential theft, and evasive tactics, the attackers have infiltrated Acme’s network. Bubba doesn’t even know he's compromised. Hunt through Microsoft Defender for Endpoint (MDE) telemetry, analyze signals, query using KQL, and follow the breadcrumbs before the keys to Bubba’s empire vanish forever.


Important Context:
- Look for the name of any suspicious file or binary that resembles an antivirus but is responsible for the malicious activity.

Known Information:
- DeviceName: anthony-001

---

## High-Level Command and Scripting Interpreter: PowerShell related IoC Discovery Plan:

1. Check DeviceFileEvents for any new suspicious file activity on the the device "anthony-001".
2. Check DeviceProcessEvents for activity involving the newly downloaded malious program.
3. Search DeviceRegistryEvents to check registry to confirm persistence activity.
4. Check DeviceEvents for suspicious activity as well. 

---

## Steps Taken

1. Searched the DeviceFileEvents for suspicious activity from "anthony-001". The primary focus was too look for activity involving new executabel files that are out of the ordinary. Discovered on May 6th at "2025-05-07T02:00:36.794406Z" a user under the account name "4nth0ny!" downloaded a file named "BitSentinelCore.exe". This is a malicous file that was trying to disguise itself as sentinel anti-virus software. THe program was donloaded via command line using the command ""csc.exe" /noconfig /fullpaths @"C:\Users\4nth0ny!\AppData\Local\Temp\c5gy0jzg\c5gy0jzg.cmdline". The attacked used tcsc.exe to downlaod the program in an attempt to disguise their actions using living off the land techniques. All this was done via remote IP "192.168.0.110" which is likely the APT's IP.
     
```kql
DeviceFileEvents 
| where DeviceName has "anthony-001"
| where InitiatingProcessAccountName contains "4nth0ny!"
| where FileName contains ".dll" or FileName contains ".exe"
```
<img width="1379" alt="Screenshot 2025-05-19 at 9 22 20 PM" src="https://github.com/user-attachments/assets/6ff376e9-1485-4ea9-a4b8-86494b7705a0" />


2. Investigated DeviceProcessEvents for any activity involving the newly downloaded malicious program. Based on the evidence in the logs on May 6th shortly after the file was downloaded at "2025-05-07T02:02:14.6264638Z" it was executed which triggered a string of events. Ultimately the file executed and it launched the command line and executed the following code ""cmd.exe" /c schtasks /Create /SC DAILY /TN "UpdateHealthTelemetry" /TR "C:\ProgramData\BitSentinelCore.exe" /ST 14:00". This command then launched this secondary command "schtasks  /Create /SC DAILY /TN "UpdateHealthTelemetry" /TR "C:\ProgramData\BitSentinelCore.exe" /ST 14:00". The end result was the creation of a scheduled task named "UpdateHealthTelemetry" which provides APT with persistance in the system. 

```kql
DeviceProcessEvents 
| where DeviceName contains "anthony-001"
| where ProcessCommandLine contains "BitSentinel"
```
<img width="1369" alt="Screenshot 2025-05-19 at 9 34 40 PM" src="https://github.com/user-attachments/assets/9b39fe91-eb35-481d-b74b-df8bf3826733" />


3. After identifying that the APT exectued their program to establish persistence, in order to confirm the DeviceRegistryEvents was investigated to look dor any registry changes. At "2025-05-07T02:02:14.9669902Z" a there was a new RefistryValueSet associated with the BitSentinelCore.exe. The registry value name was called "BitSecSvc". This confirmed that persistance was established as planed by the attacker.

```kql
DeviceRegistryEvents 
| where DeviceName == "anthony-001"
| where RegistryValueData contains "sentinel"
```
<img width="1386" alt="Screenshot 2025-05-19 at 9 41 44 PM" src="https://github.com/user-attachments/assets/7e79c1f3-42bc-47b2-9726-5bb9cf4fa8b3" />

4. Lastly the DeviceEvents log were inspected for any other activity suspicious activity on the compromised machine. Atfer searching for any activity that occured after the compromised machine has initiated the their malicous software and achieved persistence, it was discovered that they had also installed keylogging software to steal information from their target. At "2025-05-07T02:06:51.3594039Z" on May 6th a ShellLinkCreateFileEvent was created called "systemreport.lnk". This malicious file was downladed from the enternet and runs a keylogger when clicked. The threat actors took it a step further as they set it up to be initiated via userinit.exe. This means that the process would be initiated on start-up esnuring the computer is compromised at all times.

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
1. **Initial File Download and Movement**  
   **Timestamp:** 2025-02-05T05:45:12.1857689Z  
   **Device:** corp-ny-it-0334  
   **User:** bmontgomery  
   **Activity:**  
   The employee (bmontgomery) downloaded three sensitive research files:  
   - Q1-2025-ResearchAndDevelopment.pdf  
   - Q2-2025-HumanTrials.pdf  
   - Q3-2025-AnimalTrials-SiberianTigers.pdf  
   Immediately after downloading, these files were moved to the F: drive—a company-wide shared folder—potentially exposing them to any device with access to this drive.

2. **Access and Renaming on the Lobby Computer**  
   **Timestamp:** Between 2025-02-05T06:08:17.8607376Z and 2025-02-05T06:09:35.6273078Z  
   **Device:** lobby-fl2-ae5fc  
   **User:** lobbyuser  
   **Activity:**  
   The three sensitive research files were accessed on the F: drive.  
   The files were then renamed to:  
   - bryce-homework-fall-2024.pdf  
   - Amazon-Order-123456789-Invoice.pdf  
   - temp___2bbf98cf.pdf  
   **Note:** This renaming appears intended to obscure the files’ true nature and avoid immediate detection.  
   **Additional Event on Lobby Device:**  
   **Timestamp:** 2025-02-05T06:18:59.0882396Z  
   **Activity:** The program steghide.exe was downloaded. This software is known for its use in concealing data within image files, a common obfuscation technique.

3. **Data Obfuscation Using Steghide**  
   **Timestamp:** 2025-02-05T06:22:37.6603913Z  
   **Device:** lobby-fl2-ae5fc  
   **Activity:**  
   The steghide tool was executed to embed:  
   - The file bryce-homework-fall-2024.pdf into bryce-and-kid.bmp.  
   - The file Amazon-Order-123456789-Invoice.pdf into bryce-fishing.bmp.  
   **Cleanup Action:**  
   **Timestamp:** 2025-02-05T06:36:53.0523679Z  
   The steghide software was deleted from the device in an attempt to remove evidence of its use.

4. **Creation and Encryption of Zip Archive**  
   **Timestamp:** 2025-02-05T06:34:44.0874954Z  
   **Device:** lobby-fl2-ae5fc  
   **Activity:** A command using 7z.exe was executed to create a zip archive containing the newly created BMP files (which now concealed the original sensitive documents). The archive was subsequently encrypted and password-protected (using AES256 encryption) to produce an encrypted file named secure_files.zip.

5. **Renaming and Relocation of the Encrypted Archive**  
   **Timestamp:** 2025-02-05T06:46:19.3571553Z  
   **Device:** lobby-fl2-ae5fc  
   **User:** lobbyuser  
   **Activity:** The encrypted file secure_files.zip was renamed to marketing_misc.zip. The renamed file was then placed back into the F: drive.

6. **Retrieval of the Final Package by the Malicious Actor**  
   **Timestamp:** 2025-02-05T08:57:32.2582822Z  
   **Device:** corp-ny-it-0334  
   **User:** bmontgomery  
   **Activity:** The file marketing_misc.zip was taken from the F: drive and copied to the corporate device. This indicates that after performing the obfuscation and packaging on the lobby computer, bmontgomery retrieved the final package—presumably     with the intent to exfiltrate the sensitive data.

---

## Summary

An employee, bmontgomery, misused elevated privileges on device corp-ny-it-0334 by initially downloading three highly sensitive research files that were not required for his role. To conceal his actions, he transferred these files to a shared F: drive. Soon after, on a public lobby computer (lobby-fl2-ae5fc) under the account lobbyuser, the files were accessed and deceptively renamed. The attacker then downloaded and used steghide.exe to embed the files into BMP images, further obfuscating the data. To add another layer of protection against detection, these modified files were archived and encrypted with 7z.exe, with the resulting zip file being renamed before it was placed back onto the F: drive. Finally, bmontgomery later retrieved this package from the F: drive to his corporate device—indicating his intent to exfiltrate the data, although no evidence shows that the data was successfully exfiltrated.

This timeline shows a clear, methodical process where the attacker took multiple steps—from initial download and file transfer to obfuscation, encryption, and eventual retrieval—in an attempt to stealthily extract sensitive company information.

---

## Response Taken
The employee's access and account were blocked. Both the devices involved in this incident were quarantined in order to do a deep analysis. The evidence acquired during this investigation was handed over to HR to take appropriate actions. Afterwards a more thorough investigation was launched in order to identify lessons learned to avoid this incident in future scenarios. The resulting recommendations made based on the incident were more strict role based access controls, the blacklisting of software such as steghide and other similar software, and alerts set up when the use of 7zip and other data compressing files are used on company devices.  

---

## Created By:
- **Author Name**: Carlton Hurd
- **Author Contact**: https://www.linkedin.com/in/carlton-hurd-6069a5120/
- **Date**: March 4th, 2025

## Validated By:
- **Reviewer Name**: Carlton Hurd
- **Reviewer Contact**: 
- **Validation Date**: March 4th, 2025 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 4th, 2025`  | `Carlton Hurd`   
