# Threat Hunting in MDE: Investigating Tor Browser Usage

<img width="350" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

## Introduction / Objective

<p align="justify"> In this project, I conducted a threat-hunting investigation using Microsoft Defender for Endpoint (MDE) to detect unauthorized use of the Tor browser within a corporate environment. The virtual machine hosting the investigation was deployed in Microsoft Azure. The primary objective was to identify whether employees were using Tor to bypass security controls and access restricted websites, potentially violating company policies or engaging in illicit activities. </p>

## Components, Tools, and Technologies Employed

- **Cloud Environment:** Microsoft Azure (VM-hosted threat-hunting lab)
- **Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)
- **Query Language:** Kusto Query Language (KQL) for log analysis
- **Tor Browser:** To set up the main goal of this project

## Disclaimer
> The content presented here is based on my personal threat-hunting notes. Different analysts may approach investigations in varied ways, leading to differences in methodology and findings. For this project, I will focus on a single system called joshua-target-h and employee device called "employee-012". 

---

## Scenario

<p align="justify"> Management has raised concerns about the potential unauthorized use of Tor browsers within the network. Recent network logs indicate encrypted traffic patterns and connections to known Tor entry nodes. Additionally, anonymous reports suggest that employees have been discussing methods to bypass security controls and access restricted sites. <a href="https://github.com/Joshua01X/Tor-Event-Scenario-Creation">Scenario creation is in here.</a></p>

### **Threat-Hunting Objective**

- Detect any Tor browser installations or executions.
- Identify network connections related to Tor entry nodes.
- Assess any security risks associated with unauthorized Tor usage.
- Notify management of confirmed findings.

## High-Level TOR-Related IoC Discovery Plan

To detect Tor browser activity, the following forensic approach was used:

1. **File System Analysis:** Search `DeviceFileEvents` for file modifications related to `tor(.exe)`, `firefox(.exe)`, and associated executables.
2. **Process Execution Analysis:** Query `DeviceProcessEvents` for any command-line executions linked to Tor installation and operation.
3. **Network Activity Analysis:** Investigate `DeviceNetworkEvents` for outbound connections on known Tor-related ports (9001, 9030, 9040, 9050, etc.).

---

## Steps Taken

### **Step 1: Detecting Tor-Related File Events**

I first queried the `DeviceFileEvents` table to identify files containing references to Tor executables or installations. This revealed that user `employee-012` had downloaded the Tor installer and copied multiple related files to the desktop.

#### **KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "joshua-threat-h"
| where FileName has_any ("tor", "tor.exe", "firefox.exe")
| where InitiatingProcessAccountName == "employee-012"
| where Timestamp >= datetime(2025-01-30T02:44:50.9531093Z)
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/2193e5b2-79b0-4f4c-9e58-0d1ce9000200)

### **Findings:**
- **Tor Installer Downloaded:** `tor-browser-windows-x86_64-portable-14.0.4.exe` was found in `C:\Users\employee-012\Downloads`.
- **Tor Files Copied to Desktop:** Multiple Tor-related files appeared on the desktop.
- **Suspicious Document Created:** A file named `tor-shopping-list.txt` was created on `2025-01-30T03:11:53Z`.

---

### **Step 2: Detecting Tor Process Execution**

Next, I investigated `DeviceProcessEvents` to determine if `employee-012` had executed the Tor installer or browser.

#### **KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "joshua-threat-h"
| where FileName == "tor-browser-windows-x86_64-portable-14.0.4.exe"
| project Timestamp, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256
```

![image](https://github.com/user-attachments/assets/44574e68-cd65-4ee1-9b76-7cc6583d0fd2)

### **Findings:**
- **Silent Installation Executed:** The user ran `tor-browser-windows-x86_64-portable-14.0.4.exe` using a `/S` flag, indicating a silent installation.
- **Process Execution Confirmed:** Evidence showed multiple instances of `firefox.exe` and `tor.exe` running.

---

### **3. Tor Browser Execution Detection**

To determine whether the user "employee-012" launched the Tor Browser, I analyzed the `DeviceProcessEvents` table. Evidence confirms that the user executed the Tor Browser at **2025-01-30T02:49:00.2416451Z**, with multiple instances of `firefox.exe` (Tor) and `tor.exe` processes appearing in the logs.

#### **KQL Query Used to Locate Events:**
```kql
DeviceProcessEvents
| where DeviceName == "joshua-threat-h"
| where FileName has_any("tor", "tor.exe", "tor-browser.exe", "firefox.exe")
| project Timestamp, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/f8a401b8-29e9-4b2f-a1e5-78394c671fa5)

**Findings**
- **Tor Browser Execution Confirmed:** User "employee-012" launched the Tor Browser, with multiple instances of `tor.exe` and `firefox.exe` detected.
- **Persistent Tor Processes:** Logs indicate that `firefox.exe` continued running after the initial execution, suggesting repeated usage.

--- 

### **Step 4: Detecting Tor Network Connections**

To confirm whether `tor.exe` established outbound connections, I queried `DeviceNetworkEvents` for connections using known Tor-related ports.

#### **KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "joshua-threat-h"
| where InitiatingProcessAccountName == "employee-012"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/d163caa9-1010-4f00-87fd-a0d4b5e7b83c)

### **Findings:**
- **Tor Network Connection Established:** At `2025-01-30T02:52:59Z`, `tor.exe` successfully connected to `171.25.193.20:9050`.
- **No Web Browsing via Standard Ports:** There were no direct connections on ports 443 or 80.
  
---

## **Timeline of Events**

**1. Tor Browser Download** <br><br>
  **Timestamp:** 2025-01-30T02:44:50.9531093Z <br>
  **Event:** File Download <br>
  **Action:** Download of Tor Browser Installer <br>
  **File Path:** C:\Users\employee-012\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe <br>
  **Details:** The user "employee-012" downloaded the Tor Browser installer into the Downloads folder. <br>
  
**2. Tor Browser Installation and Execution** <br><br>
  **Timestamp:** 2025-01-30T02:49:00.2416451Z <br>
  **Event:** Process Creation <br>
  **Action:** Execution of Tor Installer <br>
  **Command:** tor-browser-windows-x86_64-portable-14.0.4.exe /S <br>
  **File Path:** C:\Users\employee-012\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe <br>
  **Details:** "employee-012" executed the Tor installer using a command indicating silent installation. <br>

**3. Tor Browser Access** <br><br>
  **Timestamp:** 2025-01-30T02:52:59.7254347Z <br>
  **Event:** Network Connection Established <br>
  **Action:** Outbound Connection to Tor Network <br>
  **File Path:** c:\users\employee-012\desktop\tor browser\browser\torbrowser\tor\tor.exe <br>
  **Remote IP:** 171.25.193.20 <br>
  **Remote Port:** 9050 <br>
  **Details:** The process "tor.exe" successfully established a connection to a known Tor network exit node. <br>
    
**4. Creation of Tor-Related Document** <br><br>
  **Timestamp:** 2025-01-30T03:11:53.9648164Z <br>
  **Event:** File Creation <br>
  **Action:** Creation of Suspicious Document <br>
  **File Path:** C:\Users\employee-012\Desktop\tor-shopping-list.txt <br>
  **Details:** A file named "tor-shopping-list.txt" was created, potentially containing plans or notes related to Tor Browser usage. <br>

---

## Summary of Findings 

<p align="justify">User <b>"employee-012"</b> was found to have downloaded, installed, and used the Tor Browser. Evidence confirms that the user established a direct connection to a known Tor entry node, indicating an attempt to access the anonymous network. Additionally, the creation of a file named *tor-shopping-list.txt* suggests possible intent to engage in further activities related to Tor usage, raising security concerns.</p>

## Response Taken

- **Endpoint Isolation:** Device `joshua-threat-h` was isolated to prevent further unauthorized activities.
- **Management Notified:** Direct manager of `employee-012` was informed.

## Conclusion

<p align="justify">This investigation successfully detected unauthorized Tor usage through forensic log analysis in Microsoft Defender for Endpoint. By leveraging KQL queries, I was able to track file downloads, process executions, and network connections to confirm Tor activity. The findings provide a clear pathway for security teams to take further action in mitigating unauthorized software usage in the organization. </p>
