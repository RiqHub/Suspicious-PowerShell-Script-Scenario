![image](https://github.com/user-attachments/assets/b110dcf5-1506-4f9e-bb3f-4f4f54cdbe5c)

---

# 🚨 Incident Response: Suspicious PowerShell Script Execution

---

## 🛠️ Platforms and Tools
- **Windows 10 Virtual Machines (Microsoft Azure)**
- **Microsoft Defender for Endpoint**
- **Kusto Query Language (KQL)**

---

## 📘 Scenario

John, an employee in the Accounting department, downloads a seemingly innocent PDF viewer from an untrusted website. The installation includes a hidden malicious payload that executes PowerShell scripts silently in the background.

---

## 🔍 Objective: Investigate Malicious Script Activity Using KQL
Use Microsoft Defender for Endpoint telemetry and KQL to trace script downloads, execution, persistence methods, and artifacts left behind by the attacker.

---

## 🧠 Incident Response Phases

### 1️⃣ Preparation

1. Policies and Procedures:

- Define clear procedures for handling malware infections and unauthorized script execution.

- Include actions for isolating endpoints, notifying stakeholders, and initiating forensic analysis.

- Establish software installation policies restricting the use of unauthorized applications.

2. Endpoint Security Configuration:

- Enable script block logging and process command-line logging via Group Policy or Microsoft Defender for Endpoint.

- Ensure Microsoft Defender Antivirus is set to detect and block potentially unwanted applications (PUAs).

3. Monitoring and Alerting:

- Set up custom alert rules in Microsoft Defender for Endpoint and Sentinel for PowerShell activity involving suspicious keywords (e.g., Invoke-WebRequest, -File, or known malware filenames).

- Monitor file write events in sensitive directories like C:\ProgramData and Startup.

### 2️⃣ Detection & Analysis

#### 🔸 PowerShell Script Downloads

Malicious scripts were downloaded to the hidden ProgramData folder using PowerShell's `Invoke-WebRequest`.

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

#### 🔸 Script Execution Analysis

It was confirmed that scripts with concerning names (portscan.ps1, pwncrypt.ps1, and exfiltrateddata.ps1) were downloaded to the computer. To investigate further, we checked whether these downloads had been executed, and indeed, they had been.

**Query used to locate:**

```kql
let TargetHostname = "riq-test"; 
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); 
DeviceProcessEvents
| where DeviceName == TargetHostname 
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

![image](https://github.com/user-attachments/assets/32b78ee2-83bb-4934-8daa-5e5793c50e72)

---


#### 🔸 Script Impact & Artifact Discovery

After taking a look at the details of the scripts ran (In a controlled enviroment) it was found that a ransomware script was ran, as well as a port scan to discover open vulerable ports, and a script to zip and exfiltrate employee data to spreadsheet files in the `C:\ProgramData` folder.

**Query used to locate:**

```kql
DeviceFileEvents
| where DeviceName == "riq-test"
| where FolderPath startswith @"C:\ProgramData"
```

![image](https://github.com/user-attachments/assets/d8c97c8a-59b3-47b7-b359-269d36c79a55)


---

#### 🔸 Persistence Check

After checking for any new Registry Keys or Scheduled Tasks, we searched the start up folder to see if their were any signs of persistence and we indeed found the `eicar.ps1` file that initially released the other scripts to run. 


**Query used to locate:**

```kql
DeviceFileEvents
| where FolderPath has @"\Microsoft\Windows\Start Menu\Programs\Startup"
| where ActionType in ("FileCreated", "FileModified")
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
```

![image](https://github.com/user-attachments/assets/533e9e64-5f4c-4775-b51f-49d193172f32)

### 2️⃣ Containment

- 🛑 Isolated John’s device from the network immediately.

- 🗑️ Removed all malicious scripts from the startup folder.

- 🔍 Conducted malware scans and reviewed lateral movement.

- 📢 Notified team about the presence of unauthorized software.

### 3️⃣ Eradication & Recovery

- 🔄 Performed full system wipe and rebuild of affected machine.

- 🔒 Strengthened endpoint protection settings.

- ⛔ Blocked untrusted software downloads via firewall policies.

### 4️⃣ Lessons Learned & Next Steps

- 📚 Security Awareness Training to avoid downloading unknown applications.

- 🔁 Review of allowed domains and whitelisted processes.

- 📈 Improvements to detection rules related to PowerShell behavior.

### 🧾 Summary
A suspicious PowerShell-based attack was discovered on an endpoint via an unauthorized software download. Malicious scripts executed ransomware, performed port scans, and exfiltrated data. Persistence was achieved via the startup folder, allowing repeated execution. IR actions were swiftly taken to contain, eradicate, and improve defenses.



