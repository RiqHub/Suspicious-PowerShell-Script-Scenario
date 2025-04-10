![image](https://github.com/user-attachments/assets/b110dcf5-1506-4f9e-bb3f-4f4f54cdbe5c)

# Suspicious-PowerShell-Script-Scenario

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario
John, an employee in the Accounting department, downloads a free PDF viewer from a website that appears to be legitimate but is actually untrusted. The PDF viewer installation includes a hidden malicious payload, which is designed to run a PowerShell script upon execution.

### IoC Discovery Plan

- **Check `DeviceProcessEvents`** for any signs of installation or usage.


---

## Steps Taken

### 1. Searched the `DeviceProcessEvents' Table 

First we searched the logs that triggered the alert to see if we could get any information. What was found was a request to download multiple suspicous scripts to the hidden Program Data folder. 

**Query used to locate:**

```kql
let TargetHostname = "riq-test"; 
DeviceProcessEvents
| where DeviceName == TargetHostname 
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

![image](https://github.com/user-attachments/assets/cd177c9a-85d7-436d-9be6-de0f56d700cc)

---
### 2. Searched for Scripts Ran

It was confirmed that scripts with concerning names (portscan.ps1, pwncrypt.ps1, and exfiltrateddata.ps1) were downloaded to the computer. To investigate further, we checked whether these downloads had been executed, and indeed, they had been.

**Query used to locate:**

```kql
let TargetHostname = "riq-test"; // Replace with the name of your VM as it shows up in the logs
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); 
DeviceProcessEvents
| where DeviceName == TargetHostname // Comment this line out for MORE results
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

![image](https://github.com/user-attachments/assets/32b78ee2-83bb-4934-8daa-5e5793c50e72)

---


### 3. Searched for Effect of Scripts 

After taking a look at the details of the scripts ran (In a controlled enviroment) it was found that a ransomware script was ran, as well as a port scan to discover open vulerable ports, and a script to zip and exfiltrate employee data to spreadsheet files in the `C:\ProgramData` folder.

**Query used to locate:**

```kql
DeviceFileEvents
| where DeviceName == "riq-test"
| where FolderPath startswith @"C:\ProgramData"
```

![image](https://github.com/user-attachments/assets/d8c97c8a-59b3-47b7-b359-269d36c79a55)


---



