# Timeline — DHCP Address Attribution Investigation

## 1. Observed Events

All timestamps below are local endpoint time, UTC+05:30, unless stated otherwise.

| Timestamp | Source | Event or Activity | Assessment |
|---|---|---|---|
| 21 October 2026, evening | DHCP Client Admin | Earlier SSID/cache-related events were returned by the one-day search | Wireless context only; no historical lease assignment established |
| 22 October 2026, 05:57:21 | DHCP Client Admin | Events `50065` and `50067` for SSID/cache activity | Does not establish an IPv4 lease assignment |
| 22 October 2026, 06:23:22.096 | Wazuh dashboard | Registry integrity event indexed for agent `001` | Latest supplied dashboard event |
| 22 October 2026, 06:25:34 | PowerShell screenshot | Local timestamp captured with `Get-Date` | Timestamp applies to that screenshot |
| 22 October 2026, 06:32:21 | DHCP Client Admin | Events `50065` and `50067` for SSID/cache activity | Does not establish the assigned IPv4 address |
| 22 October 2026, 06:33:11 | DHCP Client Admin | Events `50065` and `50067` for SSID/cache activity | Does not establish the assigned IPv4 address |
| 22 October 2026, 06:34:23 | DHCP Client Admin | Events `50065` and `50067` for SSID/cache activity | Does not establish the assigned IPv4 address |
| 22 October 2026, 06:35:59 | DHCP Client Admin | Events `50065` and `50067` for SSID/cache activity | Occurred shortly before the reported lease start; not proof of lease assignment |
| 22 October 2026, approximately 06:36 | Windows adapter configuration | Lease obtained for `192.168.1.6`, as reported by Windows | Establishes the lease start reported by the adapter |
| 22 October 2026, 06:55:00 | PowerShell | Current Wi-Fi DHCP configuration collected | Confirms the reported IP, MAC, DHCP server, and lease expiry |

## 2. Wazuh Telemetry Context

The Wazuh agent log recorded connection failures before a successful reconnection. The log later reported buffer pressure, including a warning that events might be lost.

Local Sysmon events were observed as late as `06:43:35`, while the latest supplied Wazuh dashboard event was timestamped `06:23:22.096`.

This establishes a discrepancy between local event generation and dashboard visibility. The exact point of failure in the ingestion pipeline remains unknown.

## 3. Troubleshooting Actions Without Confirmed Timestamps

The following actions occurred during the investigation, but exact execution timestamps were not supplied.

| Action | Result |
|---|---|
| Wazuh agent restart | Service reported `Running`; dashboard recovery was not confirmed |
| Test file creation | No corresponding dashboard event was observed |
| Process-creation test | Local Sysmon event was present; matching Wazuh event was not found |
| Wazuh manager restart | Service reported `active`; end-to-end ingestion recovery was not confirmed |
| DHCP event log search | Returned SSID/cache-related records rather than explicit historical lease evidence |
| Router administration investigation | Router credentials and model had not yet been established in the collected evidence |

These actions are not assigned invented timestamps.

## 4. Timeline Assessment

Windows reported that the current Wi-Fi lease for `192.168.1.6` began at approximately 06:36 on 22 October 2026. The DHCP Client events around this period provided SSID/cache context but did not independently establish the lease assignment.

The Wazuh dashboard's latest supplied event predates the latest observed local Sysmon events. Earlier connection failures and buffer warnings are plausible contributors to the discrepancy, but the failure point remains unconfirmed.

## 5. Outstanding Evidence

- Router DHCP lease history covering the relevant incident time.
- DHCP server records, if available.
- Manager-side evidence showing whether fresh events from agent `001` are received and processed.
- Indexer evidence showing whether fresh events are stored and searchable.
- A successful end-to-end test correlating a known local event with its corresponding Wazuh record.
