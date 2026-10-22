# Lab 114 — DHCP Address Attribution Investigation

## Overview

This lab investigates how a SOC analyst can associate an IP address with a device using DHCP lease information, network interface details, and available event records.

During the investigation, Windows reported a current DHCP lease for the Wi-Fi adapter. However, the available DHCP Client events did not establish historical IP-to-MAC attribution. A separate Wazuh telemetry gap was also encountered: newer Sysmon events were present locally but did not appear in the dashboard.

The investigation focuses on validating evidence, identifying logging limitations, and distinguishing confirmed findings from unresolved questions.

## Objectives

- Identify the active network adapter and its MAC address.
- Record the current IP address, default gateway, DHCP server, and lease period.
- Examine Windows DHCP Client event logs for lease-related evidence.
- Correlate endpoint network information with available Wazuh records.
- Investigate the difference between local Sysmon events and dashboard visibility.
- Document evidence gaps and identify the sources needed for historical attribution.

## Scenario

An analyst needs to determine which device was using a particular IP address at a relevant point in time. The analyst begins by collecting the endpoint's current network configuration and examining DHCP-related Windows events.

The endpoint reports an active Wi-Fi connection and a current DHCP lease. However, the retrieved event messages primarily describe SSID and cache activity rather than explicit historical lease assignments.

During the same investigation, Wazuh dashboard events stop appearing after approximately 06:23 on 22 October 2026, while newer events remain visible in the local Sysmon log. The analyst must document this telemetry gap separately rather than assuming the missing dashboard events prove a DHCP problem.

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

## Conclusion

The investigation documented the endpoint's current DHCP lease and examined available DHCP Client events. The collected evidence did not establish historical IP-to-MAC attribution.

Historical attribution requires records covering the relevant incident time, such as router DHCP lease history or DHCP server logs. The Wazuh telemetry gap remains a separate unresolved issue requiring manager-side and indexer-side validation.

No malicious activity or successful Wazuh recovery is claimed by this investigation.

