# Investigation Notes — DHCP Address Attribution

## 1. Investigation Summary

The objective was to determine what the available Windows network configuration, DHCP Client events, and Wazuh records could establish about IP address attribution.

The endpoint reported a current Wi-Fi DHCP lease. The retrieved DHCP Client messages primarily described SSID/cache activity and did not establish a historical lease assignment.

A separate Wazuh telemetry gap was also observed. Local Sysmon events continued after the latest supplied event in the dashboard.

## 2. Network Adapter Evidence

**Source:** PowerShell `Get-NetAdapter` output.

**Relevant fields:**

- Interface: `Wi-Fi`
- Status: `Up`
- Adapter: `Intel(R) Wi-Fi 6 AX201 160MHz`
- MAC address: `60-A5-E2-9E-84-00`

The host also had VMware virtual adapters, a WSL virtual adapter, and disconnected Bluetooth and Ethernet interfaces.

**Assessment:**

The Wi-Fi adapter was active, and its MAC address was recorded. Because the host has multiple interfaces, IP attribution must account for the network context associated with each address.

## 3. Current DHCP Lease Evidence

**Source:** `Win32_NetworkAdapterConfiguration`

**Collection time:** `2026-10-22 06:55:00 +05:30`

| Field | Observed value |
|---|---|
| Adapter | Intel(R) Wi-Fi 6 AX201 160MHz |
| MAC address | `60:A5:E2:9E:84:00` |
| DHCP enabled | `True` |
| IPv4 address | `192.168.1.6` |
| DHCP server | `192.168.1.1` |
| Lease obtained | `22-10-2026 06:36:00` |
| Lease expires | `23-10-2026 06:36:00` |

**Assessment:**

Windows reported that the Wi-Fi interface was using `192.168.1.6` under a DHCP lease associated with `192.168.1.1`.

This establishes the reported current lease state at collection time. It does not establish which IP address the device used before that lease began.

## 4. DHCP Event Channel Availability

**Source:** `Get-WinEvent -ListLog "*DHCP*"`

| Channel | Enabled | Records |
|---|---|---:|
| `Microsoft-Windows-Dhcpv6-Client/Operational` | No | Not reported |
| `Microsoft-Windows-Dhcpv6-Client/Admin` | Yes | 32 |
| `Microsoft-Windows-Dhcp-Client/Operational` | No | Not reported |
| `Microsoft-Windows-Dhcp-Client/Admin` | Yes | 2,103 |

**Assessment:**

The DHCP Client Admin log was available for investigation. The Operational channels were disabled at the time of inspection.

The disabled channels may limit the evidence available from those particular logs, but this does not establish that DHCP-related evidence is absent from other sources.

## 5. DHCP Client Event Analysis

**Source:** `Microsoft-Windows-Dhcp-Client/Admin`

The retrieved event IDs included `50065` and `50067`.

The messages referred to:

- Wireless SSID `Airtel_Vinay`
- SSID cache matching
- Receipt of SSID information
- Network address `0x60A5E29E8400`

Observed timestamps included `05:57:21`, `06:32:21`, `06:33:11`, `06:34:23`, and `06:35:59` on 22 October 2026.

**Assessment:**

These events support SSID-related activity for the Wi-Fi adapter. They do not independently prove that the device held `192.168.1.6` at each listed timestamp.

A search for address and lease-related terms returned the same types of SSID/cache events. No explicit historical lease assignment was identified in the supplied output.

## 6. Wazuh Registry Integrity Event

**Source:** Wazuh dashboard, index `wazuh-alerts-4.x-2026.10.22`

**Timestamp:** `2026-10-22 06:23:22.096`

| Field | Value |
|---|---|
| Agent name | `DESKTOP-9MMM37V` |
| Agent ID | `001` |
| Agent IP | `192.168.203.1` |
| Decoder | `syscheck_registry_value_modified` |
| Location | `syscheck` |
| Rule description | Registry Value Integrity Checksum Changed |

The affected registry value was:

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{db5917c5-ad72-4c0a-b28f-2849fffbf629}\DhcpInterfaceOptions`

The event described a scheduled integrity check and checksum change.

**Assessment:**

This event establishes that a registry-integrity record was available in Wazuh at the displayed time. It does not establish that the modification was malicious or that a DHCP lease was assigned at that time.

The Wazuh agent IP `192.168.203.1` differs from the Wi-Fi address `192.168.1.6`. The former was also observed on the host's VMware VMnet8 adapter.

## 7. Wazuh Telemetry Gap

**Observed evidence:**

- Latest supplied dashboard event: approximately `06:23:22`.
- Latest supplied local Sysmon events: up to `06:43:35`.
- Agent logs contained connection failures and subsequent reconnection.
- The agent log reported that its buffer reached 90%, became full, and that events might be lost.
- Restarting the agent did not immediately restore dashboard visibility.
- A controlled file-creation test did not produce a corresponding visible dashboard event.
- A process-creation test produced a local Sysmon event, but no matching dashboard event was found.
- The manager was restarted and reported an active service state.

**Assessment:**

The evidence demonstrates a gap between local Sysmon event generation and dashboard visibility.

The earlier connection interruption and buffer pressure are plausible contributors, but the exact failure point has not been identified. The evidence does not establish whether events failed at the agent, manager, forwarding, indexing, or dashboard stage.

A running manager service does not prove that events are being indexed successfully.

## 8. Findings Classification

### Confirmed

- The current Wi-Fi IP-to-MAC relationship reported by Windows.
- The DHCP server reported by the adapter.
- The reported lease period.
- The presence of SSID/cache-related DHCP Client events.
- A Wazuh registry-integrity event at approximately 06:23.
- A discrepancy between local Sysmon event generation and dashboard visibility.
- Earlier Wazuh connection failures and buffer warnings.

### Not confirmed

- Historical IP-to-MAC attribution for an earlier incident time.
- Availability of router or DHCP server lease history.
- The exact failure point in the Wazuh ingestion pipeline.
- A malicious cause for the registry checksum change.
- Any confirmed compromise or malicious activity.

## 9. Evidence Required to Continue

1. Router DHCP client table or lease history covering the relevant time.
2. DHCP server records, if available.
3. Manager-side evidence showing whether fresh events from agent `001` are received and processed.
4. Indexer evidence showing whether those events are stored and searchable.
5. A successful end-to-end test correlating a known local event with its corresponding Wazuh record.

## Conclusion

The available evidence is sufficient to document the current lease and the observed telemetry gap. It is insufficient to reconstruct historical IP-to-MAC attribution.

The investigation remains open pending authoritative historical DHCP records and verification of the Wazuh ingestion pipeline.
