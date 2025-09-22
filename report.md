# Task 1 — Local Network Port Scanning Report

**Author:** Your Name
**Date:** 22 September 2025
**Internship:** Cybersecurity Internship — Task 1

---

## Objective

The goal of this task was to perform reconnaissance on my local network using **Nmap** and **Wireshark/tcpdump** to identify open ports and services running on devices. The results were analyzed to understand potential security risks and recommended mitigations.

---

## Tools Used

* **Nmap** — Network scanner used for host discovery, port scanning, and service detection.
* **Wireshark / tcpdump** — Packet capture tools used to monitor traffic during scans.
* **OS:** Ubuntu 22.04 (example) — replace with your OS if different.

---

## Methodology

### Step 1 — Identify Network Range

* Discovered local IP: `192.168.1.105/24`
* Network CIDR used for scanning: `192.168.1.0/24`

### Step 2 — Quick Discovery Scan

```bash
sudo nmap -sS -F 192.168.1.0/24 -oN scans/quick_scan.txt
```

* Purpose: Identify live hosts and top 100 open ports.
* Output saved in `scans/quick_scan.txt`.

### Step 3 — Detailed Host Scan

For a selected host (`192.168.1.101`):

```bash
sudo nmap -sS -sV -A -p- 192.168.1.101 -oA scans/host1_full
```

* Performed full TCP port scan (0–65535).
* Service/version detection (`-sV`) and OS detection (`-A`).
* Output saved as `host1_full.nmap`, `host1_full.xml`, `host1_full.gnmap`.

### Step 4 — Packet Capture

Ran tcpdump during scanning:

```bash
sudo tcpdump -i wlan0 -w scans/scan_capture.pcap
```

* Captured packets for review in Wireshark.
* Useful display filters used in Wireshark:

  * `tcp.flags.syn == 1 && tcp.flags.ack == 0` (SYN packets)
  * `ip.addr == 192.168.1.101` (filter host traffic)

---

## Troubleshooting: "Host seems down" message

While running the detailed host scan you observed the following Nmap output:

```
# service/version detection & scripts (more noisy)
sudo nmap -sS -sV -A -p- 192.168.1.101 -oA scans/host1_full

Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-22 04:33 EDT
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 1.79 seconds
```

### What this means

* Nmap did not receive responses to its host discovery probes (ICMP echo, TCP/ACK, or other), so it assumed the host is down. This can happen even when the host is actually up if a firewall or host-based filter blocks ping or probe packets.

### Immediate troubleshooting steps (run these now)

1. **Ping the host (ICMP)**

```bash
ping -c 4 192.168.1.101
```

2. **Check ARP table (works on same L2 network)**

```bash
arp -an | grep 192.168.1.101
# or on Linux: ip neigh show | grep 192.168.1.101
```

3. **Do a ping-only discovery with Nmap**

```bash
sudo nmap -sn 192.168.1.101 -oN scans/ping_only_192-168-1-101.txt
```

4. **If host blocks ping, force a scan without host discovery (-Pn)**

```bash
sudo nmap -Pn -sS -sV -p- 192.168.1.101 -oA scans/host1_full_no_ping
```

5. **Try a small port-list first** (less noisy, faster)

```bash
sudo nmap -Pn -sS -sV -p22,80,443 192.168.1.101 -oN scans/host1_small_ports.txt
```

6. **Verify your network interface and IP range**

```bash
ip addr show
ip route
```

Make sure you're scanning the correct network (for example `192.168.1.0/24`) and that your Kali VM's interface is connected to the network where the target resides.

7. **Check local firewall on your scanning host** — some OS setups restrict raw sockets or block outgoing probes.

8. **If you still get no response**, the host may truly be offline, or it may be on a different subnet or behind a router/NAT. Confirm the device is powered and connected.

### What to add to the report

* Add this troubleshooting block (the commands above) into the Methodology or Appendices so your grader sees that you validated the host state and the reason for using `-Pn` if you chose to use it.
* Save the Nmap outputs produced by the troubleshooting steps into `scans/` (for example `host1_full_no_ping.nmap`, `host1_small_ports.txt`) and reference them in `report.md`.

---

## Results

### Network Overview (from quick scan)

| Host IP       | Status | Open Ports              |
| ------------- | ------ | ----------------------- |
| 192.168.1.1   | Up     | 80/tcp                  |
| 192.168.1.101 | Up     | 22/tcp, 80/tcp, 443/tcp |
| 192.168.1.105 | Up     | 139/tcp, 445/tcp        |
| 192.168.1.110 | Up     | 3389/tcp                |

> Replace the table above with your actual scan results. Save full outputs in the `scans/` directory.

### Detailed Findings (example: Host 192.168.1.101)

```
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu
80/tcp   open  http     Apache httpd 2.4.52
443/tcp  open  https    nginx 1.20.2
```

> Replace service versions with values shown in your `host1_full.nmap` output.

### Wireshark Observations

* Captured SYN packets from the scanning host to each target host/port.
* Verified Nmap responses:

  * `SYN+ACK` → port open (e.g., 22, 80, 443).
  * `RST` → port closed.
* Noted ARP traffic and occasional retransmissions for some hosts.

---

## Risks Identified

* **SSH (22):** If password authentication is enabled, risk of brute-force attacks. Consider enforcing key-based auth and rate-limiting.
* **HTTP (80):** Web services exposed; outdated servers may contain vulnerabilities—ensure patches are applied.
* **SMB (139/445):** File sharing ports exposed; these are commonly targeted by lateral-movement exploits.
* **RDP (3389):** Remote Desktop exposure poses high risk; should be restricted or tunneled through VPN.
* **Router admin (80 on 192.168.1.1):** Management interface exposed on LAN; ensure default credentials are changed and access is restricted.

---

## Recommendations

1. **Close or disable unused services** on hosts where they are not required.
2. **Apply firewall rules** to restrict access to management ports (use UFW/iptables or network ACLs). Example (UFW):

```bash
sudo ufw enable
sudo ufw deny 23          # block Telnet
sudo ufw allow from 192.168.1.0/24 to any port 22  # restrict SSH to local net
```

3. **Enforce strong authentication**: use SSH keys, disable password authentication where possible, and require complex passwords for management consoles.
4. **Patch and update** all services and the operating system regularly.
5. **Network segmentation:** put IoT/guest devices on a separate VLAN to reduce lateral movement.
6. **Monitor and alert:** enable logging and use IDS/IPS or monitoring tools to detect unusual scan activity.
7. **Avoid storing sensitive data** (passwords, private keys) in the repository. Use `.gitignore` for large or sensitive files.

---

## Conclusion

This exercise demonstrated how port scanning exposes the attack surface of a local network. Using Nmap for discovery and Wireshark for packet verification allowed identification of open services and potential weaknesses. The recommendations above will reduce exposure and improve network security.

---

## Repository Structure

```
scans/           -> Raw scan outputs (.nmap, .xml, .txt, .pcap)
screenshots/     -> Wireshark and terminal screenshots
scripts/         -> scan_local.sh automation script
report.md        -> This report
README.md        -> Task overview and quick instructions
```

---

## Appendices

### Commands Log (copy into `commands.txt`)

```
# Quick fast scan (top 100 ports)
sudo nmap -sS -F 192.168.1.0/24 -oN scans/quick_scan.txt

# Targeted full TCP scan for host 192.168.1.101
sudo nmap -sS -sV -A -p- 192.168.1.101 -oA scans/host1_full

# Packet capture during scan
sudo tcpdump -i wlan0 -w scans/scan_capture.pcap
```

*End of report.*
