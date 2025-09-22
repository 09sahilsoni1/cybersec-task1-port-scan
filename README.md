# Cyber Security Internship — Task 1: Scan Local Network for Open Ports

**Author:** Sahil Soni
**Date:** 2025-09-22

## Objective
Perform network reconnaissance on my local network to discover open ports and understand service exposure. Save scan outputs, analyze findings, and recommend remediations.

## Tools
- Nmap
- Wireshark / tcpdump
- Git / GitHub

## Steps I followed
1. Identified local network CIDR: `192.168.1.0/24`
2. Quick scan to find live hosts & top ports:
   - `sudo nmap -sS -F 192.168.1.0/24 -oN scans/quick_scan.txt`
3. Targeted scans for interesting hosts:
   - `sudo nmap -sS -sV -A -p- 192.168.1.101 -oA scans/host1_full`
4. Packet capture during scan:
   - `sudo tcpdump -i <interface> -w scans/scan_capture.pcap`
5. Analyzed PCAP in Wireshark (filters used: `tcp.flags.syn == 1 && tcp.flags.ack == 0`)

## Results (summary)
| Host IP | Open Ports | Services |
|---------|------------|----------|
| 192.168.1.101 | 22, 80, 443 | SSH, HTTP, HTTPS |
| 192.168.1.1   | 80         | Router admin page |

(Full outputs are in `scans/`)

## Risks & Recommendations
- Close/disable unused services.
- Enable firewall and restrict admin interfaces to trusted subnets.
- Patch services & remove default credentials.
- Use strong authentication (keys for SSH) and logging/monitoring.

## Files included
- `scans/` — raw nmap outputs & PCAP
- `screenshots/` — Wireshark screenshots
- `report.md` — full report with remediation steps

## Notes
Only scanned devices on my local network which I own. Do not scan networks without permission.
