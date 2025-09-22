# Task 1 — Local Network Port Scanning Report

**Author:** Sahil Soni
**Date:** 22 September 2025
**Internship:** Cybersecurity Internship — Task 1

---

## Objective

The goal of this task was to perform reconnaissance on my local network using **Nmap** and **Wireshark/tcpdump** to identify open ports and services running on devices. The results were analyzed to understand potential security risks and recommended mitigations.

---

## Tools Used

* **Nmap** — Network scanner used for host discovery, port scanning, and service detection.
* **Wireshark / tcpdump** — Packet capture tools used to monitor traffic during scans.
* **OS:** Kali Linux  

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
