#  Azure Cloud SOC & Live Honeypot Lab

##  Project Overview
In this project, I designed and deployed a cloud-native Security Operations Center (SOC) using **Microsoft Sentinel (SIEM)**. By intentionally exposing a Windows Virtual Machine (Honeypot) to the public internet, I captured and analyzed real-world RDP brute-force attacks from global threat actors in real-time.

##  Objectives
*   Provision an Azure Virtual Machine as a targeted Honeypot.
*   Configure a Log Analytics Workspace to ingest Windows Security Events.
*   Implement Microsoft Sentinel to correlate data and visualize threat actors geo-spatially using KQL.
*   Analyze raw logs (Event ID 4625) to identify attack patterns and TTPs.

##  Technologies & Tools
*   **SIEM:** Microsoft Sentinel
*   **Log Management:** Log Analytics Workspace
*   **Cloud Infrastructure:** Azure Virtual Machines (Networking, NSGs)
*   **Telemetry Generation:** Windows Event Viewer (Event ID 4625)
*   **Data Analysis:** Kusto Query Language (KQL)
*   **Scripting:** PowerShell

##  Implementation Steps

### 1. Honeypot Exposure (Firewall Deactivation)
To ensure the Honeypot was visible to automated internet scanners, I utilized PowerShell to disable all local firewall profiles. This allowed ingress ICMP and RDP traffic to reach the OS for telemetry collection.
> <img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/e489479d-c1dc-4039-afcc-fc37d372e175" />


### 2. Connectivity Validation
Verified global visibility by performing ICMP echo requests (Ping) from a remote terminal to the public IP of the instance located in **Sweden Central**.
> <img width="979" height="509" alt="image" src="https://github.com/user-attachments/assets/515a4c8b-2658-4820-9abe-680d365a1705" />


### 3. Log Ingestion & Telemetry
Configured the **Azure Monitor Agent (AMA)** to stream raw security events to the SIEM. Below is an example of an **Event ID 4625 (Audit Failure)** captured during a simulated brute-force attempt.
> <img width="787" height="550" alt="image" src="https://github.com/user-attachments/assets/99b25b7c-0b37-48d0-bc4b-49f70e79fde3" />


### 4. Threat Intelligence Visualization
Using custom **Kusto Query Language (KQL)**, I extracted geolocation data from the attackers' IPs to populate a live Threat Intelligence Map.
> <img width="1635" height="710" alt="image" src="https://github.com/user-attachments/assets/9d4b56bd-e64e-455d-81c2-d45c45ab5eb4" />


## 🕵️ Technical Artifact (KQL Query)
```kql
SecurityEvent
| where EventID == 4625
| extend Location = geo_info_from_ip_address(IpAddress)
| extend Country = tostring(Location.country), Latitude = toreal(Location.latitude), Longitude = toreal(Location.longitude)
| summarize AttackCount = count() by IpAddress, Country, Latitude, Longitude
