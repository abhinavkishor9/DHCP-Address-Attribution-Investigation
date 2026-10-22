# DHCP-Address-Attribution-Investigation
## Overview
### What Is DHCP Address Attribution?

Dynamic Host Configuration Protocol (DHCP) automatically assigns network configuration to devices, including an IPv4 address, subnet mask, default gateway, and other network settings. A DHCP server typically maintains lease information that associates an assigned address with a client identifier, often derived from the device's MAC address.

In security investigations, **DHCP address attribution** is the process of determining which device was using a particular IP address at a specific point in time. This is important because IP addresses can change as leases expire, renew, or are reassigned to other devices.

### Why Is It Important in SOC Investigations?

Security tools commonly record IP addresses when reporting suspicious connections, authentication activity, or other network events. However, an IP address alone may not reliably identify the device that generated the activity.

An analyst may need to correlate several sources of evidence:

- **Endpoint network configuration:** Identifies the device's current IP address, MAC address, gateway, DHCP server, and lease details.
- **DHCP Client event logs:** May provide information about DHCP-related activity, depending on the events recorded and the logging configuration.
- **DHCP server or router lease records:** Can provide historical associations between client identifiers and assigned IP addresses, if the relevant records were retained.
- **SIEM telemetry:** Helps correlate network configuration evidence with endpoint and security events collected over time.

### Current Configuration vs. Historical Attribution

A critical distinction is that a device's current IP configuration does not prove which IP address it used during an earlier incident. Likewise, the presence of a DHCP-related event does not automatically prove that a lease was assigned, renewed, or changed.

Reliable historical attribution requires evidence that corresponds to the relevant time period. The analyst should consider timestamps, client identifiers, lease details, time zones, and the possibility that an address was reassigned.

### Challenges and Limitations

Several factors can complicate attribution:

- A Windows endpoint may have physical and virtual network adapters, each with its own IP address and MAC address.
- DHCP logs may be disabled, incomplete, rotated, or lack the specific event needed to establish an address assignment.
- Router or DHCP server logs may not retain historical lease information for the period under investigation.
- SIEM ingestion delays or collection failures may create gaps between locally generated events and events visible in the dashboard.
- Registry integrity alerts and other related events require contextual analysis and should not be treated as direct proof of DHCP activity or malicious behavior.

### Investigation Principle

**IP address attribution must be based on time-correlated evidence, not assumptions.** A sound investigation records what the available evidence confirms, identifies what remains unknown, and specifies which additional records are needed to reach a reliable conclusion.

This lab investigates how a SOC analyst can associate an IP address with a device using DHCP lease information, network interface details, and available event records.

During the investigation, Windows reported a current DHCP lease for the Wi-Fi adapter. However, the available DHCP Client events did not establish historical IP-to-MAC attribution. A separate Wazuh telemetry gap was also encountered: newer Sysmon events were present locally but did not appear in the dashboard.

The investigation focuses on validating evidence, identifying logging limitations, and distinguishing confirmed findings from unresolved questions.

## Lab Objectives

- Determine the endpoint's current IPv4 address, MAC address, default gateway, DHCP server, and lease validity using Windows network configuration evidence.
- Correlate the active network adapter's MAC address with available DHCP Client event records to identify what the logs can reliably establish about the endpoint's network connection.
- Examine Windows DHCP Client logs for evidence of address acquisition, renewal, release, or other DHCP-related activity without treating every DHCP event as proof of a lease assignment.
- Distinguish current network configuration from historical IP address attribution and identify the limitations of relying exclusively on endpoint logs.
- Review available Wazuh telemetry to assess whether relevant endpoint events are reaching the SIEM and separate local event generation from successful collection and indexing.
- Evaluate registry integrity alerts and other related records in context, avoiding unsupported conclusions about malicious activity or DHCP changes.
- Document confirmed findings, unresolved questions, evidence gaps, and the additional DHCP server or router lease records required to establish historical IP-to-device attribution.
- Develop an evidence-based investigation timeline that supports accurate SOC reporting and clearly distinguishes verified facts from assumptions.
  
## Lab Scenario

A SOC analyst is asked to investigate which device was using a particular IPv4 address during a period of interest. Reliable address attribution is important when investigating suspicious network connections, reviewing security alerts, or correlating activity across endpoint and network logs.

The investigation begins on a Windows endpoint connected to a Wi-Fi network. The analyst collects the current network configuration, identifies the active adapter's MAC address, and reviews the available Windows DHCP Client event logs for records that could help explain the device's network configuration. The analyst must determine whether the available evidence establishes only the current configuration or also supports historical IP-to-device attribution.

During the review, the analyst encounters several evidence limitations:
- Available DHCP Client events primarily describe SSID and network-cache activity rather than clearly documenting an IPv4 lease assignment.
- The endpoint has multiple virtual network adapters, so its different IP addresses must be associated with the correct interfaces.
- Wazuh contains a registry integrity event related to TCP/IP interface configuration, but the event does not independently establish that a DHCP lease changed or that malicious activity occurred.
- Recent endpoint events are visible locally, while corresponding recent telemetry is not consistently visible in the Wazuh dashboard.

The analyst must correlate the available evidence without treating current configuration as proof of past activity. The investigation should distinguish verified observations from unresolved questions, assess the telemetry gap, and identify what additional records would be needed to confirm historical address attribution.

The expected outcome is an evidence-based investigation record that documents the endpoint's observed network configuration, relevant DHCP and Wazuh findings, collection limitations, and the next steps required to establish a reliable historical IP-to-device association.

## Environment

| Component | Details |
|---|---|
| Endpoint | `DESKTOP-9MMM37V` |
| Operating system | Windows 11 Pro |
| Wi-Fi adapter | Intel(R) Wi-Fi 6 AX201 160MHz |
| Wi-Fi MAC address | `60-A5-E2-9E-84-00` |
| Current Wi-Fi IPv4 address | `192.168.1.6` |
| Default gateway | `192.168.1.1` |
| DHCP server reported by Windows | `192.168.1.1` |
| Wireless SSID | `Airtel_Vinay` |
| Endpoint monitoring | Sysmon and Wazuh Agent |
| Wazuh agent ID | `001` |
| Wazuh agent name | `DESKTOP-9MMM37V` |
| Wazuh manager | `192.168.203.129` |
| Wazuh agent IP shown in the dashboard | `192.168.203.1` |
| Investigation date | 22 October 2026 |

The endpoint also has VMware and WSL virtual network adapters. Their addresses belong to separate network contexts and must not be confused with the Wi-Fi address.

## Investigation Workflow

### 1. Identify the network interfaces

The following command lists network adapters, their status, MAC addresses, and descriptions.

```powershell
Get-NetAdapter |
    Select-Object Name, Status, MacAddress, InterfaceDescription
```

The Wi-Fi adapter was active and reported MAC address `60-A5-E2-9E-84-00`. VMware and WSL virtual adapters were also present.

### 2. Collect the current DHCP lease

The following command retrieves the Wi-Fi adapter's current DHCP configuration.

```powershell
$adapter = Get-CimInstance Win32_NetworkAdapterConfiguration |
    Where-Object {
        $_.Description -eq "Intel(R) Wi-Fi 6 AX201 160MHz"
    }

[PSCustomObject]@{
    CollectionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
    Adapter        = $adapter.Description
    MACAddress     = $adapter.MACAddress
    DHCPEnabled    = $adapter.DHCPEnabled
    IPAddress      = $adapter.IPAddress -join ", "
    DHCPServer     = $adapter.DHCPServer
    LeaseObtained  = $adapter.DHCPLeaseObtained
    LeaseExpires   = $adapter.DHCPLeaseExpires
} | Format-List
```

The observed configuration was:

- MAC address: `60:A5:E2:9E:84:00`
- DHCP enabled: `True`
- IPv4 address: `192.168.1.6`
- DHCP server: `192.168.1.1`
- Lease obtained: approximately 06:36 on 22 October 2026
- Lease expires: approximately 06:36 on 23 October 2026

These values establish the current lease reported by Windows, not the endpoint's complete address history.

### 3. Identify available DHCP event logs

```powershell
Get-WinEvent -ListLog "*DHCP*" -ErrorAction SilentlyContinue |
    Select-Object LogName, IsEnabled, RecordCount
```

The inspection identified these channels:

| Event log | Enabled | Records |
|---|---|---:|
| `Microsoft-Windows-Dhcpv6-Client/Operational` | No | Not reported |
| `Microsoft-Windows-Dhcpv6-Client/Admin` | Yes | 32 |
| `Microsoft-Windows-Dhcp-Client/Operational` | No | Not reported |
| `Microsoft-Windows-Dhcp-Client/Admin` | Yes | 2,103 |

The enabled DHCP Client Admin log was examined for relevant records.

### 4. Review recent DHCP Client events

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Dhcp-Client/Admin"
    StartTime = (Get-Date).AddHours(-2)
} -ErrorAction SilentlyContinue |
    Select-Object -First 30 TimeCreated, Id, LevelDisplayName, Message |
    Format-List
```

The retrieved records included event IDs `50065` and `50067`. Their messages described SSID cache matching and receipt of the wireless SSID `Airtel_Vinay` for the adapter with network address `0x60A5E29E8400`.

These records provide wireless SSID-related context. They do not independently establish the assigned IPv4 address at each event timestamp.

### 5. Search for lease-related evidence

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = "Microsoft-Windows-Dhcp-Client/Admin"
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match '192\.168\.1\.|lease|leased|address|DHCP server|renew|assigned'
    } |
    Select-Object -First 40 TimeCreated, Id, Message |
    Format-List
```

The supplied output continued to show SSID/cache-related events rather than explicit lease assignments.

No historical IP-to-MAC mapping was established from these records.

### 6. Review the Wazuh dashboard evidence

The latest supplied dashboard event was timestamped `2026-10-22 06:23:22.096`.

Relevant fields included:

- Agent name: `DESKTOP-9MMM37V`
- Agent ID: `001`
- Agent IP: `192.168.203.1`
- Decoder: `syscheck_registry_value_modified`
- Location: `syscheck`
- Rule description: `Registry Value Integrity Checksum Changed`

The event described a scheduled integrity check that detected a checksum change in the registry value `DhcpInterfaceOptions` under a TCP/IP interface registry path.

This is a registry-integrity event, not proof of a DHCP lease assignment or malicious modification.

The agent IP shown in the dashboard differs from the Wi-Fi address. The endpoint's VMware VMnet8 adapter was observed with address `192.168.203.1`, so the addresses represent different network contexts.

### 7. Investigate the Wazuh telemetry gap

Local Sysmon events were observed after the latest supplied Wazuh dashboard event. The agent log contained earlier manager connection failures, followed by reconnection and warnings that the agent buffer had become full and events might be lost.

The Wazuh agent was restarted, but dashboard visibility did not immediately recover. A test file did not result in a corresponding visible dashboard event. A process-creation test produced a local Sysmon event, but no matching event appeared in Wazuh.

The Wazuh manager was then restarted and reported an active service state. This did not confirm that fresh events were being processed and indexed successfully.

The telemetry issue remained unresolved at the end of the collected evidence.

## Findings

### Confirmed

- Windows reported that the Wi-Fi adapter was active with MAC address `60-A5-E2-9E-84-00`.
- The current Wi-Fi IPv4 address was reported as `192.168.1.6`.
- The DHCP server and default gateway were reported as `192.168.1.1`.
- The reported lease began at approximately 06:36 on 22 October 2026.
- DHCP Client events included SSID/cache-related event IDs `50065` and `50067`.
- The latest supplied Wazuh dashboard event was timestamped `06:23:22.096`.
- Local Sysmon events continued after the latest supplied dashboard event.
- Wazuh agent logs recorded connection interruptions and buffer pressure.
- Restarting the agent and manager did not demonstrate successful end-to-end recovery.

### Unresolved

- Historical IP-to-MAC attribution for an earlier incident time.
- Whether router DHCP history or DHCP server lease logs are available.
- The exact point where Wazuh event ingestion or indexing stopped progressing.
- Whether the registry checksum change was related to any DHCP activity.
- Whether any malicious activity occurred.

