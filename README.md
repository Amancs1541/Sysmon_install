## Sysmon Overview

According to Microsoft documentation, **System Monitor (Sysmon)** is a Windows system service and device driver that monitors and logs system activity to the Windows event log. Once installed, it persists through reboots and provides detailed insights into:

* Process creation
* Network connections
* Changes to file creation times

By forwarding these logs to a SIEM or other log analysis tools, Sysmon helps detect malicious or anomalous activity and gives valuable visibility into how attackers operate within your network.

> **Note:** In a production environment, Sysmon logs are usually forwarded to a SIEM. However, in this scenario, we’ll focus on viewing Sysmon events locally via **Windows Event Viewer**, located at:

```
Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
```

---

## Sysmon Configuration Overview

Sysmon requires a **configuration file** to define how events are monitored and filtered. You can either:

* **Create your own config**, or
* **Download** high-quality community configs such as:

  * **SwiftOnSecurity Sysmon-Config**
  * **ION-Storm config fork** – takes a more proactive “include” approach.

Most configs use **exclusion-based rules** to reduce noise and focus on anomalies. However, the choice between inclusion and exclusion depends on your organization's needs and SOC team preferences. Be flexible and willing to adapt as necessary.

---

## Key Sysmon Event IDs

Here are some of the most important Event IDs and how they're used within config files:

---

### 🔹 Event ID 1: Process Creation

Logs every process created on the system. Useful for detecting suspicious or typoed processes.

```xml
<RuleGroup name="" groupRelation="or">
  <ProcessCreate onmatch="exclude">
    <CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
  </ProcessCreate>
</RuleGroup>
```

**Use Case**: Excludes known benign process to reduce log volume.

---

### 🔹 Event ID 3: Network Connection

Monitors outbound network connections. Useful for detecting unauthorized tools or communications.

```xml
<RuleGroup name="" groupRelation="or">
  <NetworkConnect onmatch="include">
    <Image condition="image">nmap.exe</Image>
    <DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>
  </NetworkConnect>
</RuleGroup>
```

**Use Case**: Flags suspicious binaries (like `nmap.exe`) and known malicious ports (like Metasploit’s 4444).

---

### 🔹 Event ID 7: Image Loaded

Tracks DLLs loaded into processes. Can indicate DLL injection or hijacking.

```xml
<RuleGroup name="" groupRelation="or">
  <ImageLoad onmatch="include">
    <ImageLoaded condition="contains">\Temp\</ImageLoaded>
  </ImageLoad>
</RuleGroup>
```

**Use Case**: Detects DLLs loaded from suspicious locations like the `\Temp\` directory.

**Caution**: Can cause performance issues due to high event volume.

---

### 🔹 Event ID 8: CreateRemoteThread

Detects code injection by monitoring threads created in other processes.

```xml
<RuleGroup name="" groupRelation="or">
  <CreateRemoteThread onmatch="include">
    <StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>
    <SourceImage condition="contains">\</SourceImage>
  </CreateRemoteThread>
</RuleGroup>
```

**Use Case**: Detects potential Cobalt Strike beacons and anomalous thread injections.

---

### 🔹 Event ID 11: File Created

Monitors new or overwritten files.

```xml
<RuleGroup name="" groupRelation="or">
  <FileCreate onmatch="include">
    <TargetFilename name="Alert,Ransomware" condition="contains">HELP_TO_SAVE_FILES</TargetFilename>
  </FileCreate>
</RuleGroup>
```

**Use Case**: Flags files often created by ransomware.

---

### 🔹 Event IDs 12 / 13 / 14: Registry Events

Tracks registry key and value creation/modification.

```xml
<RuleGroup name="" groupRelation="or">
  <RegistryEvent onmatch="include">
    <TargetObject name="T1484" condition="contains">Windows\System\Scripts</TargetObject>
  </RegistryEvent>
</RuleGroup>
```

**Use Case**: Detects persistence mechanisms using script locations in the registry.

---

### 🔹 Event ID 15: FileCreateStreamHash

Monitors the creation of Alternate Data Streams (ADS) – often used to hide malware.

```xml
<RuleGroup name="" groupRelation="or">
  <FileCreateStreamHash onmatch="include">
    <TargetFilename condition="end with">.hta</TargetFilename>
  </FileCreateStreamHash>
</RuleGroup>
```

**Use Case**: Flags suspicious `.hta` files in ADS.

---

### 🔹 Event ID 22: DNS Query

Logs all DNS queries. Ideal for spotting unusual or malicious domains.

```xml
<RuleGroup name="" groupRelation="or">
  <DnsQuery onmatch="exclude">
    <QueryName condition="end with">.microsoft.com</QueryName>
  </DnsQuery>
</RuleGroup>
```

**Use Case**: Reduces noise by excluding trusted domains like `.microsoft.com`.

---

## Conclusion

Sysmon is a powerful tool for endpoint visibility and threat hunting. With customizable configs and granular Event ID controls, it forms a crucial layer in a defense-in-depth strategy. Depending on your environment and threat model, choose between **inclusion-heavy** or **exclusion-heavy** configurations, and continuously tune rules for effectiveness.

## ⚙️ Sysmon Best Practices
Practice	Description
Exclude > Include	Exclude known good activity to avoid false positives while still catching suspicious behavior.

Use CLI tools	Tools like Get-WinEvent and wevutil.exe allow granular filtering far beyond what Event Viewer allows.

Know Your Environment	Tailor rules to what's “normal” in your network to better catch anomalies.

🛠️ Filtering Logs
📋 Using Event Viewer
Use Filter Current Log to apply EventID-based filters.

XML filters are possible, but manual and not scalable.

⚡ Using PowerShell
Use Get-WinEvent for custom XPath queries.

Get-WinEvent -Path <PathToLog.evtx> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'

🔍 Filter Syntax Summary
By Event ID:
*/System/EventID=ID

By XML Attribute Name:
*/EventData/Data[@Name="Attribute"]

By Event Data Value:
*/EventData/Data=Value

## 🔹 Basic XPath Structure for Sysmon Logs
Sysmon logs follow a standard event structure:

```xml
Copy
Edit
<Event>
  <System>
    <EventID>3</EventID>
    ...
  </System>
  <EventData>
    <Data Name="Image">C:\malware.exe</Data>
    <Data Name="DestinationPort">4444</Data>
    ...
  </EventData>
</Event>
```

| Goal                            | XPath Filter                                       |
| ------------------------------- | -------------------------------------------------- |
| **Filter by EventID**           | `*/System/EventID=3`                               |
| **Filter by Data Name**         | `*/EventData/Data[@Name="Image"]`                  |
| **Filter by Data Value**        | `*/EventData/Data='C:\malware.exe'`                |
| **Filter by Attribute + Value** | `*/EventData/Data[@Name="DestinationPort"]='4444'` |
