# Nmap

## Overview

I completed four TryHackMe rooms covering how Nmap discovers hosts, scans ports, identifies services, and saves results. These notes summarise the concepts I learned and provide a practical reference for future labs.

## Rooms Covered

- Nmap Live Host Discovery
- Nmap Basic Port Scans
- Nmap Advanced Port Scans
- Nmap Post Port Scans

## 1. Nmap Live Host Discovery

Before checking services, I learned how to identify which devices are online. A machine can block ordinary ping requests and still be reachable through other protocols.

### What I Learned

- **ARP discovery** finds devices on the same local IPv4 network. It does not work across routers.
- **ICMP discovery** uses echo, timestamp, or address-mask requests to look for replies.
- **TCP discovery** sends SYN or ACK probes. Responses can reveal a live host even when ICMP is blocked.
- **UDP discovery** can identify hosts through UDP replies or relevant ICMP errors.
- **Reverse DNS** can reveal useful hostnames, but names alone do not confirm a device's role.

### Useful Commands

The commands in this file are revision examples, not my original scan results. Replace `TARGET_IP` and `LAB_SUBNET` with authorised lab targets. Examples use Linux; `sudo` supplies the privileges needed for raw-packet scans.

```bash
# Discover live hosts without scanning ports
nmap -sn LAB_SUBNET

# Use ARP discovery on the local network
sudo nmap -sn -PR LAB_SUBNET

# Use TCP SYN probes on ports 80 and 443
sudo nmap -sn -PS80,443 TARGET_IP
```

**Remember:** `-sn` skips port scanning. `-Pn` skips normal host discovery and treats targets as online; it does not bypass filtering. `-n` disables DNS lookups, while `-iL targets.txt` reads targets from a file.

## 2. Nmap Basic Port Scans

Once a host is identified, port scanning helps determine which services may be accessible.

### What I Learned

- **TCP connect (`-sT`):** completes the TCP handshake when a port is open.
- **TCP SYN (`-sS`):** sends SYN and checks the reply without completing the normal handshake. SYN/ACK indicates open; RST indicates closed.
- **UDP (`-sU`):** checks UDP ports separately. A UDP reply indicates open; ICMP port unreachable indicates closed. No reply can mean open or filtered.

### Understanding the Results

| Port State | Meaning |
| --- | --- |
| `open` | A service is accepting traffic. |
| `closed` | The port is reachable, but no service is listening. |
| `filtered` | Filtering prevents Nmap from determining whether the port is open. |
| `unfiltered` | Reachable, but the scan cannot determine whether it is open. |
| `open\|filtered` | Could be open or filtered; the evidence is inconclusive. |
| `closed\|filtered` | Could be closed or filtered; possible with idle scans. |

### Useful Commands

```bash
# TCP connect scan on selected ports
nmap -sT -p 22,80,443 TARGET_IP

# SYN scan of TCP ports 1–65535
sudo nmap -sS -p- TARGET_IP

# Scan selected UDP ports
sudo nmap -sU -p 53,123,161 TARGET_IP
```

A default scan checks the **1,000 most common TCP ports**. `-F` checks 100, while `-p-` covers ports 1–65535 for the selected protocol.

I also learned how timing templates (`-T0` to `-T5`), packet rates, and parallel probes affect performance. Increasing speed too aggressively can cause missed results.

**Key takeaway:** an open port is a starting point for investigation, not proof of a vulnerability.

## 3. Nmap Advanced Port Scans

This room explored how different TCP flags and packet responses help reveal port behaviour and filtering.

### What I Learned

- **Null (`-sN`):** sends a TCP packet with no flags.
- **FIN (`-sF`):** sends only the FIN flag.
- **Xmas (`-sX`):** sends FIN, PSH, and URG together.
- **Maimon (`-sM`):** sends FIN/ACK and relies on behaviour found in certain BSD-derived systems.
- **ACK (`-sA`):** helps identify filtering. A RST response means unfiltered, not necessarily open.
- **Window (`-sW`):** examines the TCP window in RST responses; reliability depends on the target.
- **Custom scans:** `--scanflags` selects TCP flags manually.

For Null, FIN, and Xmas scans, a RST generally indicates closed, while silence means `open|filtered`. These techniques do not behave reliably on every operating system.

### Additional Concepts

I also covered **source spoofing, decoys, fragmentation, and idle/zombie scans**. Spoofing changes apparent source information; decoys mix additional sources into scan traffic. Fragmentation splits supported probes into smaller packets. Idle scanning infers port states from changes in a suitable idle host's IP ID counter.

These techniques depend on network and target behaviour. They do not guarantee anonymity or bypass modern security controls.

```bash
# Try a Xmas scan in the lab
sudo nmap -sX -p 80,443 TARGET_IP

# Examine filtering and show the reason behind each result
sudo nmap -sA -p 80,443 --reason TARGET_IP
```

For troubleshooting, `-v` adds detail, `--packet-trace` displays sent and received packets, and `-d` enables debugging.

**Key takeaway:** understand why Nmap reports a state. No response does not automatically mean an open port.

## 4. Nmap Post Port Scans

After finding ports, I learned how to identify the services behind them and preserve the results.

### What I Learned

- **Service detection (`-sV`):** probes services to identify software and versions. A port number alone cannot confirm which service is running.
- **OS detection (`-O`):** estimates the operating system from network responses. Results are more reliable when an open and a closed TCP port are available.
- **Traceroute (`--traceroute`):** helps map the network path to the target.
- **Nmap Scripting Engine:** automates checks such as collecting web titles and service information. `-sC` runs default scripts; `--script` selects specific scripts. Review scripts before running them, since some are intrusive.

```bash
# Identify services on discovered ports
nmap -sV -p 22,80,443 TARGET_IP

# Estimate the operating system
sudo nmap -O TARGET_IP

# Collect a web page title
nmap -sV --script http-title -p 80,443 TARGET_IP

# Save service results in three formats
nmap -sV -p 22,80,443 -oA service-scan TARGET_IP
```

`-oA service-scan` creates `.nmap` (readable text), `.xml` (structured output), and `.gnmap` (older grepable output) files. Individual formats can be saved with `-oN`, `-oX`, and `-oG`.

**Remember:** `-A` combines OS detection, version detection, default scripts, and traceroute. It does not scan every port.

## My Main Takeaways

1. Discover hosts, identify ports, then investigate the services behind them.
2. Check TCP and UDP separately and choose port coverage deliberately.
3. Interpret responses in context, especially ambiguous or filtered results.
4. Verify service versions and OS guesses before drawing conclusions.
5. Save the command and output so findings can be reviewed later.

## References

- [TryHackMe — Nmap Live Host Discovery](https://tryhackme.com/room/nmap01)
- [TryHackMe — Nmap Basic Port Scans](https://tryhackme.com/room/nmap02)
- [TryHackMe — Nmap Advanced Port Scans](https://tryhackme.com/room/nmap03)
- [TryHackMe — Nmap Post Port Scans](https://tryhackme.com/room/nmap04)
- [Official Nmap Reference Guide](https://nmap.org/book/man.html)
