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



