# Timeline 
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

