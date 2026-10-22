# Troubleshooting Notes — DHCP Attribution and Wazuh Telemetry

## 1. Purpose

This document records the issues encountered while investigating DHCP address attribution and Wazuh telemetry on 22 October 2026.

The DHCP attribution problem and the Wazuh dashboard gap are separate issues. The troubleshooting steps should not imply that resolving one automatically resolves the other.

## 2. Wazuh Dashboard Stopped Showing Recent Events

### Symptom

The latest supplied dashboard event was timestamped approximately `06:23:22`, while local Sysmon events were observed later.

### Evidence

The Wazuh agent log contained connection failures followed by a successful reconnection to the manager. It also reported buffer pressure and warned that events might be lost.

### Action Taken

The Wazuh agent service was restarted.

The service reported `Running`, but the expected fresh event did not appear in the dashboard.

The Wazuh manager service was subsequently restarted and reported `active`.

### Result

Successful end-to-end event ingestion was not confirmed.

### Interpretation

The connection interruption and buffer warnings may have contributed to the telemetry gap. However, the available evidence does not establish the precise failure point or prove that every missing event was lost during the interruption.

### Next Action

Inspect the manager-side event-processing pipeline and the indexer. Establish whether fresh events from agent `001` reach the manager, are processed, and are indexed.

Avoid repeating service restarts without evidence identifying a service-level fault.

## 3. Test File Did Not Produce a Visible Dashboard Event

### Symptom

A test file was created at:

`C:\WazuhRecoveryTest.txt`

No corresponding event appeared in the dashboard.

### Interpretation

File creation does not guarantee that Sysmon generates Event ID 11. Generation depends on the active Sysmon configuration and whether the activity is monitored.

Therefore, the missing dashboard event alone could not establish whether local event generation had occurred.

### Follow-up

A process-creation test was performed. The local Sysmon log contained a process-creation event, but no corresponding event was found in Wazuh.

### Lesson

Verify that a test event exists in the source log before using it to test downstream ingestion. Then search for the exact event in the receiving system.

## 4. DHCP Search Did Not Establish Historical Lease Attribution

### Symptom

The DHCP Client Admin log contained records, but the returned messages were primarily SSID/cache-related rather than explicit lease assignments.

### Actions Taken

- Enumerated available DHCP-related event channels.
- Checked which channels were enabled.
- Queried recent DHCP Client Admin events.
- Searched the previous day for address, lease, renewal, assignment, and DHCP server terms.

### Result

The supplied output did not establish a historical IP-to-MAC mapping.

### Interpretation

The current lease is available from Windows, but the event messages examined do not provide the historical assignment needed for attribution.

The disabled Operational channels may limit evidence available from those logs, but their disabled state does not prove that the required records are unavailable elsewhere.

### Next Action

Inspect the router's DHCP client table and lease history. If the router does not retain historical records, determine whether another authoritative DHCP server or network log source exists.

Do not infer historical address ownership from the current lease alone.

## 5. Multiple IP Addresses Caused Attribution Ambiguity

### Observed Addresses

| Address | Context |
|---|---|
| `192.168.1.6` | Wi-Fi IPv4 address |
| `192.168.1.1` | Wi-Fi default gateway and reported DHCP server |
| `192.168.203.1` | VMware VMnet8 host-side adapter; also shown as the Wazuh agent IP |
| `192.168.203.129` | Wazuh manager |
| `192.168.174.1` | VMware VMnet1 adapter |
| `172.31.160.1` | WSL virtual adapter |

### Interpretation

The endpoint uses multiple network interfaces with different addresses. The Wazuh agent IP should not be treated as the endpoint's Wi-Fi address.

### Lesson

Correlate records using the correct interface, MAC address, IP address, timestamp, and network context.

## 6. Registry Integrity Event Was Not Proof of DHCP Assignment

### Symptom

Wazuh reported a registry checksum change involving the `DhcpInterfaceOptions` value under a TCP/IP interface registry path.

### Interpretation

The event was decoded as a registry value modification detected by scheduled integrity monitoring. The registry path is related to network configuration, but the event does not independently prove a DHCP lease assignment, unauthorized modification, or malicious behavior.

### Lesson

Interpret an event according to its source, decoder, message, and surrounding evidence. A DHCP-related registry value is not equivalent to a DHCP lease event.

## 7. Changes Avoided

During this investigation:

- No duplicate Sysmon event-channel collection block was added.
- No DHCP settings were changed.
- No router DHCP reservation was created.
- No router factory reset was performed.
- No Wazuh configuration was edited as part of the DHCP attribution investigation.

The Wazuh agent and manager services were restarted during telemetry troubleshooting. These actions did not establish successful end-to-end recovery.

## 8. Status Summary

| Item | Status |
|---|---|
| Current DHCP lease collected | Confirmed |
| Wi-Fi MAC address collected | Confirmed |
| DHCP Client logs examined | Completed |
| Historical IP-to-MAC attribution | Unresolved |
| Wazuh agent restarted | Completed |
| Wazuh manager restarted | Completed |
| End-to-end Wazuh recovery | Not confirmed |
| Router DHCP history examined | Pending |
| Manager/indexer pipeline validated | Pending |

## 9. Lessons Learned

- Current DHCP configuration does not establish historical IP ownership.
- Check actual event messages instead of assuming that a DHCP-related log contains lease assignments.
- Local Sysmon generation and dashboard ingestion are different stages.
- A running service does not prove successful event processing or indexing.
- Buffer warnings establish possible event loss but do not identify the complete failure path.
- Multiple virtual and physical interfaces require careful network-context correlation.
- Document confirmed observations separately from hypotheses and unresolved findings.
